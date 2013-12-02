open Lwt
open Tls
open TlsEngineNG

let test_server () =
  let ctx = empty_context () in
  let s_sock = init_server_connection 1234 in
  accept_client s_sock >>= fun c_sock ->
  run_automata server_automata ServerNil "" ctx c_sock

let _ =
  Unix.handle_unix_error Lwt_unix.run (test_server ())
