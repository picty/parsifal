open BasePTypes
open PTypes
open Lwt
open TlsEnums
open Tls
open Ssl2
open Parsifal


(**********************)
(* Record preparation *)
(**********************)

let mk_rec ct v content = { content_type = ct; record_version = v; record_content = content }

let extract_first_record enrich ctx recs =
  let rec produce_raw_first_record accu recs =
    match accu, recs with
    | _, [] -> accu, []
    | None, r::rs ->
      let content = POutput.create () in
      dump_record_content content r.record_content;
      produce_raw_first_record (Some (r.content_type, r.record_version, content)) rs
    | Some (ct, v, content), r::rs ->
      if r.content_type = ct && r.record_version = v
      then begin
	dump_record_content content r.record_content;
	produce_raw_first_record accu rs
      end else accu, rs
  in

  match produce_raw_first_record None recs with
  | None, rs -> rs
  | Some (ct, v, content), rs ->
    let input_name = "Merged " ^ (string_of_tls_content_type ct) ^ " records" in
    let rec_content = POutput.contents content in

    (* Here, we try to enrich the first record from the merged messages *)
    let new_input = input_of_string ~enrich:enrich input_name rec_content in
    let res = match try_parse ~report:false (parse_record_content ctx ct) new_input with
      | None ->
	let first = mk_rec ct v (Unparsed_Record rec_content) in
	first::rs
      | Some res ->
	let first = mk_rec ct v res in
	let next =
	  if (eos new_input)
	  then rs
	  else begin
	    (* If we have not used all the contents of the merged records, we must keep it *)
	    let rem = parse_rem_binstring new_input in
	    let next_record = mk_rec ct v (Unparsed_Record rem) in
	    next_record::rs
	  end
	in first::next
    in
    res

(* Offline record parsing *)
let parse_all_records input prefs =
  let rec parse_raw_records accu i =
    if eos i
    then List.rev accu, None
    else begin
      match try_parse (parse_tls_record None) i with
      | Some next -> parse_raw_records (next::accu) i
      | None -> List.rev accu, Some (parse_rem_binstring i)
    end
  in

  let rec enrich_records ctx accu recs =
    match extract_first_record input.enrich (Some ctx) recs with
    | [] -> List.rev accu
    | { record_content = Unparsed_Record _ }::_ -> List.rev_append accu recs
    | r::rs -> enrich_records ctx (r::accu) rs
  in

  let recs, remaining = parse_raw_records [] { input with enrich = NeverEnrich } in
  let ctx = empty_context prefs in
  let parsed_recs = enrich_records ctx [] recs in
  parsed_recs, Some ctx, remaining




(******************)
(* Global context *)
(******************)

type tls_global_context = {
  certs : X509.certificate list;
}




(********************)
(* Simple functions *)
(********************)

let update_with_client_hello ctx ch =
  (* TODO: Take the record version into account? *)
  ctx.future.proposed_versions <- (V_SSLv3, ch.client_version);
  ctx.future.f_client_random <- ch.client_random;
  ctx.future.f_session_id <- ch.client_session_id;
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
  ctx.future.f_server_random <- sh.server_random;
  ctx.future.f_session_id <- sh.server_session_id;
  (* TODO: exts *)
  match sh.server_extensions with
  | None | Some [] -> ()
  | _ -> () (* "Extensions not supported for now" *)

let update_with_certificate ctx certs =
  ctx.future.f_certificates <- certs

let update_with_server_key_exchange ctx ske =
  ctx.future.f_server_key_exchange <- ske


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
  ctx.future.proposed_versions <- ctx.preferences.acceptable_versions;
  ctx.future.proposed_ciphersuites <- ctx.preferences.acceptable_ciphersuites;
  ctx.future.proposed_compressions <- ctx.preferences.acceptable_compressions;
  let ch = {
    client_version = snd ctx.future.proposed_versions;
    client_random = String.make 32 '\x00'; (* TODO! *)
    client_session_id = ""; (* TODO? *)
    ciphersuites = ctx.future.proposed_ciphersuites;
    compression_methods = ctx.future.proposed_compressions;
    client_extensions = None (* TODO! *)
  } in
  update_with_client_hello ctx ch;
  mk_handshake_msg ctx HT_ClientHello (ClientHello ch)

let rec find_first_match preferred_list other_list =
  match preferred_list with
  | [] -> None
  | x::xs ->
    if List.mem x other_list
    then Some x
    else find_first_match xs other_list

let mk_server_hello ctx =
  let pref_cs, other_cs, pref_cm, other_cm =
    if ctx.preferences.directive_behaviour
    then ctx.preferences.acceptable_ciphersuites, ctx.future.proposed_ciphersuites,
      ctx.preferences.acceptable_compressions, ctx.future.proposed_compressions
    else ctx.future.proposed_ciphersuites, ctx.preferences.acceptable_ciphersuites,
      ctx.future.proposed_compressions, ctx.preferences.acceptable_compressions
  in
  let cs = match find_first_match pref_cs other_cs with
    | None -> failwith "TODO: Incompatible lists!"
    | Some suite -> suite
  and cm = match find_first_match pref_cm other_cm with
    | None -> failwith "TODO: Incompatible lists!"
    | Some compression -> compression
  in

  let sh = {
    server_version = snd ctx.future.proposed_versions;
    server_random = ctx.future.f_client_random; (* TODO! *)
    server_session_id = ""; (* TODO! *)
    ciphersuite = cs;
    compression_method = cm;
    server_extensions = None (* TODO! *)
  } in
  update_with_server_hello ctx sh;
  mk_handshake_msg ctx HT_ServerHello (ServerHello sh)

let mk_certificate_msg ctx = mk_handshake_msg ctx HT_Certificate (Certificate [])

let mk_server_hello_done ctx = mk_handshake_msg ctx HT_ServerHelloDone ServerHelloDone



(************************)
(* Automata description *)
(************************)

exception ConnectionTimeout

type automata_input =
  | InputSSL2Msg of ssl2_record
  | InputTlsMsg of tls_record
  | Timeout
  | InternalMsgIn of string
  | Nothing
  | EndOfFile

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
  | Abort
  | Wait
  | OutputSSL2Msgs of ssl2_record list
  | OutputTlsMsgs of tls_record list
  | InternalMsgOut of string
  | FatalAlert of tls_alert_type



(************************************)
(* Automata input/output generators *)
(************************************)

let catch_eof = function
  | ParsingException (OutOfBounds, _)
  | End_of_file -> return EndOfFile
  | e -> fail e


type connection_options = {
  timeout : float option;
  verbose : bool;
  plaintext_chunk_size : int;
}
let default_options = {
  timeout = Some 5.0;
  verbose = false;
  plaintext_chunk_size = 16384;
}

type connection = {
  socket : Lwt_unix.file_descr;
  options : connection_options;
  mutable input : string_input;
  (* TODO: Handle SSLv2 records? *)
  mutable input_records : tls_record list;
  mutable output : string;
}

type server_socket = {
  s_socket : Lwt_unix.file_descr;
  s_options : connection_options;
}


let init_client_connection ?options host port =
  let s = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  Lwt_unix.gethostbyname host >>= fun host_entry ->
  let inet_addr = host_entry.Unix.h_addr_list.(0) in
  let addr = Unix.ADDR_INET (inet_addr, port) in
  let t = Lwt_unix.connect s addr in
  let timed_t = match options with
    | None | Some { timeout = None } -> t
    | Some { timeout = Some timeout_val } ->
      pick [t; Lwt_unix.sleep timeout_val >>= fun () -> fail ConnectionTimeout]
  in
  let peer_name = host^":"^(string_of_int port) in
  timed_t >>= fun () -> return {
    socket = s;
    options = pop_opt default_options options;
    input = input_of_string ~enrich:NeverEnrich peer_name ""; input_records = [];
    output = "";
  }


let init_server_connection ?options ?bind_address:(bind_addr=None) ?backlog:(backlog=1024) port =
  let s = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  let inet_addr = match bind_addr with
    | Some a -> Unix.inet_addr_of_string a
    | None -> Unix.inet_addr_any
  in
  let local_addr = Unix.ADDR_INET (inet_addr, port) in
  Lwt_unix.setsockopt s Unix.SO_REUSEADDR true;
  Lwt_unix.bind s local_addr;
  Lwt_unix.listen s backlog;
  { s_socket = s; s_options = pop_opt default_options options }

let accept_client s =
  Lwt_unix.accept s.s_socket >>= fun (sock, peer_info) ->
  let peer_name = match peer_info with
    | Unix.ADDR_INET (a, p) -> (Unix.string_of_inet_addr a)^":"^(string_of_int p)
    | _ -> "Unknown peer info"
  in
  let i = input_of_string ~enrich:NeverEnrich peer_name ""
  and o = "" in
  return { socket = sock; options = s.s_options;
	   input = i; input_records = [];
	   output = o }


let get_next_automata_input ctx c =
  let timeout_t = match c.options.timeout with
    | None -> []
    | Some t -> [Lwt_unix.sleep t >>= fun () -> return Timeout]
  in

  let rec input_fun () =
    (* TODO: 4096 should be adjustable *)
    let buf = String.make 4096 ' ' in
    Lwt_unix.read c.socket buf 0 4096 >>= fun n_read ->
    (* TODO: Handle n_read = 0 correctly *)
    c.input <- append_to_input c.input (String.sub buf 0 n_read);
    let rec parse_new_records new_record =
      (* TODO: In fact, we are stuck if input enriches too much here  *)
      (* TODO: Should we check for that? *)
      match try_parse (parse_tls_record None) c.input with
      | None -> new_record
      | Some ({ record_version = v; content_type = ct; record_content = Unparsed_Record ciphertext } as r) ->
	c.input <- drop_used_string c.input;
	let plaintext = ctx.in_expand (ctx.in_decrypt v ct ciphertext) in
	c.input_records <- c.input_records@[{r with record_content = Unparsed_Record plaintext}];
	parse_new_records true
      | Some _ -> failwith "get_next_automata_input: unexpected early parsed record"
    in
    enrich_new_records (parse_new_records false)

  and enrich_new_records new_record_pending =
    if new_record_pending then begin
      (* TODO: Should it really be AlwaysEnrich here? *)
      match extract_first_record AlwaysEnrich (Some ctx) c.input_records with
      | [] | [ { record_content = Unparsed_Record _ } ] -> input_fun ()
      | r::rs ->
	c.input_records <- rs;
	return (InputTlsMsg r)
    end else input_fun ()
  in

  let output_fun () =
    let len = String.length c.output in
    Lwt_unix.write c.socket c.output 0 len >>= fun n_written ->
    c.output <- String.sub c.output n_written (len - n_written);
    return Nothing
  in

  match c.input_records with
    | [] | { record_content = Unparsed_Record _ }::_ ->
      let input_t = if c.input_records = [] then [input_fun ()] else [enrich_new_records true] in
      let rec output_t =
	if c.output = ""
	then []
	else [output_fun ()]
      in
      try_bind (fun () -> pick (input_t@output_t@timeout_t)) return catch_eof

    | r::_ -> return (InputTlsMsg r)



let output_record ctx conn r =
  let size =
    if conn.options.plaintext_chunk_size > 0
    then conn.options.plaintext_chunk_size
    else 16384
  in
  let ct = r.content_type
  and v = r.record_version
  and content = exact_dump_record_content r.record_content in
  let len = String.length content in
  let result = POutput.create () in
  POutput.add_string result conn.output;

  let rec mk_records offset =
    if offset < len then begin
      let next_offset =
	if offset + size >= len
	then len
	else offset + size
      in
      let plaintext = String.sub content offset (next_offset - offset) in
      let ciphertext = ctx.out_encrypt v ct (ctx.out_compress plaintext) in
      let next = { content_type = ct;
		   record_version = v;
		   record_content = Unparsed_Record ciphertext } in
      dump_tls_record result next;
      mk_records next_offset
    end
  in

  mk_records 0;
  conn.output <- POutput.contents result



(************)
(* Automata *)
(************)

let client_automata state input _global_ctx ctx =
  match state, input with
  | ClientHelloSent, InputTlsMsg { record_content = Handshake { handshake_content = ServerHello sh } } ->
    update_with_server_hello ctx sh;
    ServerHelloReceived, Wait
  | ServerHelloReceived, InputTlsMsg { record_content = Handshake { handshake_content = Certificate certs } } ->
    update_with_certificate ctx certs;
    CertificateReceived, Wait
  | CertificateReceived, InputTlsMsg { record_content = Handshake { handshake_content = ServerKeyExchange ske } } ->
    update_with_server_key_exchange ctx ske;
    SKEReceived, Wait
  | (CertificateReceived | SKEReceived),
    InputTlsMsg { record_content = Handshake { handshake_content = ServerHelloDone } } ->
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
  get_next_automata_input ctx sock >>= fun automata_input ->
  let next_state, action = automata state automata_input global_ctx ctx in
  let again = match action with
    | OutputTlsMsgs rs ->
      List.iter (output_record ctx sock) rs;
      true
    | FatalAlert at ->
      let r = mk_alert_msg ctx AL_Fatal at in
      sock.output <- sock.output ^ (exact_dump_tls_record r);
      false
    | Wait -> true
    | Abort -> false

    | OutputSSL2Msgs _
    | InternalMsgOut _ -> print_endline "Something else to do"; false
  in
  if again
  then run_automata automata next_state global_ctx ctx sock
  else return next_state
