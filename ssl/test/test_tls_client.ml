open Lwt
open Parsifal
open PTypes
open TlsEnums
open Tls
open TlsEngineNG

let test_client host port prefs =
  let ctx = { (empty_context prefs) with direction = Some ClientToServer } in
  resolve host port >>= (fun resolved_host -> init_client_connection resolved_host) >>= fun c_sock ->
  let ch () = mk_client_hello ctx in
  output_record ctx c_sock ch;
  run_automata client_automata ClientHelloSent "" ctx c_sock >>= fun _ ->
  let print_certs = function
    | Parsed (_, cert) ->
      print_endline (String.concat ", " (List.map X509Basics.string_of_atv (List.flatten cert.X509.tbsCertificate.X509.subject)))
    | _ -> ()
  in
  List.iter print_certs ctx.future.f_certificates;
  Lwt_unix.close c_sock.socket

let _ =
  if Array.length Sys.argv <> 3
  then begin
    prerr_endline "Usage: test_tls_client [host] [port]";
    exit 1
  end;
  try
    TlsDatabase.enrich_suite_hash ();
    let host = Sys.argv.(1)
    and port = int_of_string Sys.argv.(2) in
    let prefs = {
      (default_prefs DummyRNG) with
        acceptable_ciphersuites = [TLS_RSA_WITH_RC4_128_MD5; TLS_RSA_WITH_AES_128_CBC_SHA]
    } in
    Unix.handle_unix_error Lwt_unix.run (test_client host port prefs)
  with
    | ParsingException (e, h) -> prerr_endline (string_of_exception e h); exit 1
    | e -> prerr_endline (Printexc.to_string e)
