open Lwt
open Parsifal
open PTypes
open TlsEnums
open Tls
open TlsEngineNG

let test_client port prefs =
  let ctx = empty_context prefs in
  init_client_connection "localhost" port >>= fun c_sock ->
  let ch = mk_client_hello ctx in
  output_record c_sock ch;
  run_automata client_automata ClientHelloSent "" ctx c_sock >>= fun _ ->
  let print_certs = function
    | Parsed cert ->
      print_endline (String.concat ", " (List.map X509Basics.string_of_atv (List.flatten cert.X509.tbsCertificate.X509.subject)))
    | _ -> ()
  in
  List.iter print_certs ctx.future.s_certificates;
  Lwt_unix.close c_sock.socket

let _ =
  Unix.handle_unix_error Lwt_unix.run (test_client 8080 Tls.default_prefs)
