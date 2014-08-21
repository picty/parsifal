open Lwt
open Parsifal
open PTypes
open TlsEnums
open Tls
open TlsEngineNG

let test_client port prefs =
  let ctx = { (empty_context prefs) with direction = Some ClientToServer } in
  resolve "localhost" port >>= init_client_connection >>= fun c_sock ->
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
  try
    TlsDatabase.enrich_suite_hash ();
    Unix.handle_unix_error Lwt_unix.run (test_client 8080 (default_prefs DummyRNG))
  with
    | ParsingException (e, h) -> prerr_endline (string_of_exception e h); exit 1
    | e -> prerr_endline (Printexc.to_string e)
