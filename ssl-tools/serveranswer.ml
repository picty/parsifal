open Lwt
open Unix
open Getopt
open Parsifal
open LwtUtil
open TlsEnums
open Tls


let verbose = ref false

type action =
  | FatalAlert
  | HandshakeAnswer
  | StandardAnswer (* tries a HS if conform *)
let action = ref StandardAnswer
let set_action value = TrivialFun (fun () -> action := value)

let alert_type = ref AT_HandshakeFailure
(* TODO: Wrap this in a try with and send Usage/ActionDone *)
let update_alert_type at = alert_type := tls_alert_type_of_string at; ActionDone

let record_version = ref V_TLSv1
let server_version = ref V_TLSv1
let update_version r s = r := tls_version_of_string s; ActionDone
let ciphersuite = ref TLS_RSA_WITH_RC4_128_MD5
let update_ciphersuite cs = ciphersuite := ciphersuite_of_string cs; ActionDone
let compression_method = ref CM_Null
let update_compression_method cm = compression_method := compression_method_of_string cm
let server_random = ref (String.make 32 ' ')

let certfile = ref ""
let certcontent = ref ""
let skefile = ref ""
let base64 = ref true
let port = ref 8080

let options = [
  mkopt (Some 'h') "help" Usage "show this help";
  mkopt (Some 'v') "verbose" (Set verbose) "print more info to stderr";
  mkopt None "pem" (Set base64) "use PEM format to read certificate";
  mkopt None "der" (Clear base64) "use DER format";

  mkopt (Some 'A') "alert" (set_action FatalAlert) "always send back a fatal alert";
  mkopt (Some 'H') "handshake" (set_action HandshakeAnswer) "always answers with handshake messages";
  mkopt None "standard-answer" (set_action StandardAnswer) "use a standard behaviour (default)";

  mkopt None "alert-type" (StringFun update_alert_type) "sets the alert type to send";

  mkopt None "record-version" (StringFun (update_version record_version)) "sets the record version";
  mkopt None "server-version" (StringFun (update_version server_version)) "sets the version used in ServerHello";
  mkopt (Some 'c') "ciphersuite" (StringFun update_ciphersuite) "sets the ciphersuite chosen by the server";
  mkopt None "server-random" (StringVal server_random) "sets the random string sent by the server (must be 32-bit long)";

  mkopt (Some 'C') "certificate" (StringVal certfile) "sets the certificate to send (there should only be one)";
  mkopt None "server-key-exchange" (StringVal skefile) "sets the ServerKeyExchange to send";

  mkopt (Some 'p') "port" (IntVal port) "binds the socket to this port";
]



(* TODO: Handle exceptions in lwt code, and add timers *)

let write_record o record =
  let s = exact_dump_tls_record record in
  really_write o s

let send_hs_record o (t, content) = 
  let r = {
    content_type = CT_Handshake;
    record_version = !record_version;
    record_content = Handshake {
      handshake_type = t;
      handshake_content = content;
    }
  } in
  write_record o r


let rec print_msgs i =
  lwt_parse_tls_record None i >>= fun record ->
  if !verbose then print_string (print_value (value_of_tls_record record));
  if record.content_type = CT_Handshake
  then print_msgs i
  else return (flush Pervasives.stdout)


let send_alert o at =
  let r = {
    content_type = CT_Alert;
    record_version = !record_version;
    record_content = Alert {
      alert_type = at;
      alert_level = AL_Fatal
    }
  } in
  write_record o r


let send_hs o sh_version =
  let sh = HT_ServerHello, ServerHello {
    server_version = sh_version;
    server_random = !server_random;
    server_session_id = "";
    ciphersuite = !ciphersuite;
    compression_method = !compression_method;
    server_extensions = None;
  }
  and certs = HT_Certificate, Certificate [UnparsedCertificate !certcontent]
    (* TODO: SKE *)
  and shd = HT_ServerHelloDone, ServerHelloDone
  in
  Lwt_list.iter_s (send_hs_record o) [sh; certs; shd]


(* TODO: Handle record sizes *)

 (* write_record s { content_type = CT_Alert; record_version = ch.client_version; record_content = Unparsed_Record "\x02\x28\xdc\xbc\xea\x4d\xf6\x3e\x3a\xbf\xbe" } >>= fun () -> *)
(* write_record s { content_type = CT_Alert; record_version = ch.client_version; record_content = Unparsed_Record "\x01\x5a\x02\x28gjlkmfjlfdsjlfjfsdjlkm" } >>= fun () -> *)
(*  write_record s { content_type = CT_Alert; record_version = ch.client_version; record_content = Unparsed_Record "\x02\x28" } >>= fun () -> *)
  (* write_record s { content_type = CT_Alert; record_version = ch.client_version; record_content = Unparsed_Record "\x01\x28" } >>= fun () -> *)
(*  write_record s { content_type = CT_Alert; record_version = ch.client_version; record_content = Unparsed_Record "\x02" } >>= fun () ->
    write_record s { content_type = CT_Alert; record_version = ch.client_version; record_content = Unparsed_Record "\x28" } >>= fun () -> *)


let expect_clienthello s =
  input_of_fd "Socket" s >>= fun input ->
  lwt_parse_tls_record None input >>= fun record ->
  if !verbose then print_string (print_value (value_of_tls_record record));
  let answer_thread = match record.record_content, !action with
    | _, FatalAlert -> send_alert s !alert_type
    | _, HandshakeAnswer -> send_hs s !server_version
    | Handshake {handshake_content = ClientHello ch}, StandardAnswer ->
      if (int_of_tls_version !record_version < int_of_tls_version ch.client_version) &&
	(List.mem !ciphersuite ch.ciphersuites)
      then begin
	let real_version = min ch.client_version !server_version in
	send_hs s real_version
      end else send_alert s AT_HandshakeFailure
    | _ -> fail (Failure "ClientHello expected")
  in
  answer_thread >>= fun () -> print_msgs input


let new_socket () =
  Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0
let local_addr =
  Unix.ADDR_INET (Unix.inet_addr_any, !port)

let catcher = function
  | ParsingException (e, h) ->
    Lwt_io.write_line Lwt_io.stderr (string_of_exception e h)
  | e ->
    Lwt_io.write_line Lwt_io.stderr (Printexc.to_string e)



let rec accept sock =
  Lwt_unix.accept sock >>= fun (s, _) ->
  catch (fun () -> expect_clienthello s) catcher >>= fun () ->
  ignore (Lwt_unix.close s);
  accept sock

let _ =
  try
    let args = parse_args ~progname:"serveranswer" options Sys.argv in
    if !certfile <> ""
    then begin
      let parse_fun =
	if !base64
	then Base64.parse_base64_container Base64.AnyHeader X509.parse_certificate
	else X509.parse_certificate
      in
      certcontent := exact_dump X509.dump_certificate (exact_parse parse_fun (string_input_of_filename !certfile))
    end else usage "serveranswer" options (Some "Please provide a certificate.");
    begin
      match args with
      | [] -> ()
      | _ -> failwith "Invalid command"
    end;
    enrich_record_content := true;
    let socket = new_socket () in
    Lwt_unix.setsockopt socket Unix.SO_REUSEADDR true;
    Lwt_unix.bind socket local_addr;
    Lwt_unix.listen socket 1024;
    Lwt_unix.run (accept socket)
  with
    | ParsingException (e, h) -> prerr_endline (string_of_exception e h); exit 1
    | e -> prerr_endline (Printexc.to_string e); exit 1
