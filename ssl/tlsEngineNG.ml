open PTypes
open Lwt
open TlsEnums
open Tls
open Ssl2
open Parsifal

(* TODO: Rewrite TlsUtil.clean_records to parse the real records one
   by one (to let TlsEngine handle the context evolution properly) *)


(* Global context *)

type tls_global_context = {
  certs : X509.certificate list;
}




(* Simple functions *)

let update_with_client_hello ctx ch =
  (* TODO: Take the record version into account? *)
  ctx.future.proposed_versions <- (V_SSLv3, ch.client_version);
  ctx.future.s_client_random <- ch.client_random;
  ctx.future.s_session_id <- ch.client_session_id;
  ctx.future.proposed_ciphersuites <- ch.ciphersuites;
  ctx.future.proposed_compressions <- ch.compression_methods;
  (* TODO: extensions *)
  match ch.client_extensions with
  | None | Some [] -> ()
  | _ -> () (* For now, all extensions are ignored *)

let update_with_server_hello ctx sh =
  (* Checks? *)
  ctx.future.proposed_versions <- (sh.server_version, sh.server_version);
  ctx.future.proposed_ciphersuites <- [sh.ciphersuite];
  ctx.future.proposed_compressions <- [sh.compression_method];
  ctx.future.s_server_random <- sh.server_random;
  ctx.future.s_session_id <- sh.server_session_id;
  (* TODO: exts *)
  match sh.server_extensions with
  | None | Some [] -> ()
  | _ -> failwith "Extensions not supported for now"

let update_with_certificate ctx certs =
  ctx.future.s_certificates <- certs


let mk_alert_msg ctx alert_level alert_type = {
  content_type = CT_Alert;
  record_version = ctx.current_version;
  record_content = Alert {
    alert_level = alert_level;
    alert_type = alert_type;
  }
}

let mk_handshake_msg ctx hs_type hs_msg = {
  content_type = CT_Handshake;
  record_version = ctx.current_version;
  record_content = Handshake {
    handshake_type = hs_type;
    handshake_content = hs_msg
  }
}

let mk_client_hello ctx =
  (* TODO: Use ctx!!!! *)
  let ch = {
    client_version = V_TLSv1;
    client_random = String.make 32 '\x00';
    client_session_id = "";
    ciphersuites = [TLS_RSA_WITH_RC4_128_SHA];
    compression_methods = [CM_Null];
    client_extensions = None
  } in
  update_with_client_hello ctx ch;
  mk_handshake_msg ctx HT_ClientHello (ClientHello ch)

let mk_server_hello ctx =
  (* TODO: Use ctx!!!! *)
  let sh = {
    server_version = snd ctx.future.proposed_versions;
    (* Bouh !!! *)
    server_random = ctx.future.s_client_random;
    server_session_id = "";
    ciphersuite = List.hd ctx.future.proposed_ciphersuites;
    compression_method = List.hd ctx.future.proposed_compressions;
    server_extensions = None
  } in
  update_with_server_hello ctx sh;
  mk_handshake_msg ctx HT_ServerHello (ServerHello sh)

let mk_certificate_msg ctx = mk_handshake_msg ctx HT_Certificate (Certificate [])

let mk_server_hello_done ctx = mk_handshake_msg ctx HT_ServerHelloDone ServerHelloDone


(* Automata description *)

type automata_input =
  | InputSSL2Msg of ssl2_record
  | InputTlsMsg of tls_record
  | Timeout
  | InternalMsgIn of string
  | Nothing

type tls_client_state =
  | ClientNil
  | ClientHelloSent
  | ServerHelloReceived
  | CertificateReceived
  | SKEReceived
  | SHDReceived

type tls_server_state =
  | ServerNil
  | ClientHelloReceived

type automata_output =
  | Wait
  | ResetTimeoutAndWait
  | OutputSSL2Msgs of ssl2_record list
  | OutputTlsMsgs of tls_record list
  | InternalMsgOut of string
  | FatalAlert of tls_alert_type


(* Automata input generators *)

type connection = {
  socket : Lwt_unix.file_descr;
  timeout : int option;
  verbose : bool;
  mutable input : string_input;
  mutable input_records : tls_record list;
  mutable output : string;
}

type server_socket = {
  s_socket : Lwt_unix.file_descr;
  s_timeout : int option;
  s_verbose : bool;
}


let init_client_connection ?timeout:(timeout=Some 5) ?verbose:(verbose=true) host port =
  let s = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  Lwt_unix.gethostbyname host >>= fun host_entry ->
  let inet_addr = host_entry.Unix.h_addr_list.(0) in
  let addr = Unix.ADDR_INET (inet_addr, port) in
  let t = Lwt_unix.connect s addr in
  let timed_t = match timeout with
    | None -> t
    | Some timeout_val ->
      pick [t; Lwt_unix.sleep (float_of_int timeout_val) >>= fun () -> fail (Failure "Timeout")]
  in
  let peer_name = host^":"^(string_of_int port) in
  timed_t >>= fun () -> return {
    socket = s;
    timeout = timeout; verbose = verbose;
    input = input_of_string peer_name ""; input_records = [];
    output = "";
  }



let init_server_connection ?bind_address:(bind_addr=None) ?backlog:(backlog=1024) ?timeout:(timeout=Some 5) ?verbose:(verbose=true) port =
  let s = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  let inet_addr = match bind_addr with
    | Some a -> Unix.inet_addr_of_string a
    | None -> Unix.inet_addr_any
  in
  let local_addr = Unix.ADDR_INET (inet_addr, port) in
  Lwt_unix.setsockopt s Unix.SO_REUSEADDR true;
  Lwt_unix.bind s local_addr;
  Lwt_unix.listen s backlog;
  { s_socket = s; s_timeout = timeout; s_verbose = verbose } 

let accept_client s =
  Lwt_unix.accept s.s_socket >>= fun (sock, peer_info) ->
  let peer_name = match peer_info with
    | Unix.ADDR_INET (a, p) -> (Unix.string_of_inet_addr a)^":"^(string_of_int p)
    | _ -> "Unknown peer info"
  in
  let i = input_of_string peer_name ""
  and o = "" in
  return { socket = sock; verbose = s.s_verbose;
	   timeout = s.s_timeout;
	   input = i; input_records = [];
	   output = o }


let get_next_automata_input ctx c =
  match c.input_records with
    | [] | { record_content = Unparsed_Record _ }::_ ->
      let timeout_t = match c.timeout with
	| None -> []
	| Some t -> [Lwt_unix.sleep (float_of_int t) >>= fun () -> return Timeout]
      in

      let rec input_fun () =
	(* TODO: 4096 should be adjustable *)
	let buf = String.make 4096 ' ' in
        (* TODO: Handle Unix exception *)
	Lwt_unix.read c.socket buf 0 4096 >>= fun n_read ->
	c.input <- append_to_input c.input (String.sub buf 0 n_read);
	let rec parse_new_records new_record =
	  match try_parse (parse_tls_record None) c.input with
	  | None -> new_record
	  | Some r ->
	    c.input <- drop_used_string c.input;
	    c.input_records <- c.input_records@[r];
	    parse_new_records true
	in
	if parse_new_records false then begin
	  match TlsUtil.clean_records ctx ~verbose:c.verbose ~enrich:AlwaysEnrich c.input_records with
	  | [] | { record_content = Unparsed_Record _ }::_ -> input_fun ()
	  | r::rs ->
	    c.input_records <- rs;
	    return (InputTlsMsg r)
	end else input_fun ()
      in
      let input_t = [input_fun ()] in

      let output_fun () =
	let len = String.length c.output in
	Lwt_unix.write c.socket c.output 0 len >>= fun n_written ->
	c.output <- String.sub c.output n_written (len - n_written);
	return Nothing
      in
      let rec output_t =
	if c.output = ""
	then []
	else [output_fun ()]
      in
      pick (input_t@output_t@timeout_t)

    | r::_ -> return (InputTlsMsg r)


(* Automata *)

let client_automata state input _global_ctx ctx =
  match state, input with
  | ClientHelloSent, InputTlsMsg { record_content = Handshake { handshake_content = ServerHello sh } } ->
    update_with_server_hello ctx sh;
    ServerHelloReceived, Wait
  | ServerHelloReceived, InputTlsMsg { record_content = Handshake { handshake_content = Certificate certs } } ->
    update_with_certificate ctx certs;
    CertificateReceived, Wait
  | CertificateReceived, InputTlsMsg { record_content = Handshake { handshake_content = ServerHelloDone } } ->
    SHDReceived, FatalAlert AT_BadCertificate
  | _, Timeout -> ClientNil, FatalAlert AT_CloseNotify
  | _, Nothing -> state, Wait
  | _ -> ClientNil, FatalAlert AT_HandshakeFailure

let server_automata state input _global_ctx ctx =
  match state, input with
  | ServerNil, InputTlsMsg { record_content = Handshake { handshake_content = ClientHello ch } } ->
(*    let ctx = empty_crypto_context () in *)
    update_with_client_hello ctx ch;
    let sh = mk_server_hello ctx in
    let cert = mk_certificate_msg ctx in
    let shd = mk_server_hello_done ctx in
    ClientHelloReceived, OutputTlsMsgs [sh; cert; shd]
  | _, Timeout -> ServerNil, FatalAlert AT_CloseNotify
  | _, Nothing -> state, Wait
  | _ -> ServerNil, FatalAlert AT_HandshakeFailure



let rec run_automata automata state global_ctx ctx sock =
  get_next_automata_input (Some ctx) sock >>= fun automata_input ->
  let next_state, action = automata state automata_input global_ctx ctx in
  let again = match action with
    | OutputTlsMsgs rs ->
      List.iter (fun r -> sock.output <- sock.output ^ (exact_dump_tls_record r)) rs;
      true
    | FatalAlert at ->
      let r = mk_alert_msg ctx AL_Fatal at in
      sock.output <- sock.output ^ (exact_dump_tls_record r);
      false
    | Wait -> true
    | _ -> print_endline "Something else to do"; false
  in
  if again
  then run_automata automata next_state global_ctx ctx sock
  else return ()
