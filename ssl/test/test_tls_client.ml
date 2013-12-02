open Lwt
open Parsifal
open PTypes
open TlsEnums
open Tls
open TlsEngineNG

let test_client () =
  let ctx = empty_context () in
  ctx.future.s_version <- V_TLSv1;
  init_client_connection "localhost" 4433 >>= fun c_sock ->
  let ch = mk_client_hello ctx in
  c_sock.output <- exact_dump dump_tls_record ch;
  run_automata client_automata ClientHelloSent "" ctx c_sock >>= fun () ->
  let print_certs = function
    | Parsed cert ->
      print_endline (String.concat ", " (List.map X509Basics.string_of_atv (List.flatten cert.X509.tbsCertificate.X509.subject)))
    | _ -> ()
  in
  List.iter print_certs ctx.future.s_certificates;
  return ()

let _ =
  Unix.handle_unix_error Lwt_unix.run (test_client ())
