open Lwt
open Tls
open TlsEngineNG

let test_server prefs =
  let ctx = empty_context prefs in
  let s_sock = init_server_connection 1234 in
  accept_client s_sock >>= fun c_sock ->
  run_automata server_automata ServerNil "" ctx c_sock >>= fun _ ->
  Lwt_unix.close c_sock.socket

let _ =
  Unix.handle_unix_error Lwt_unix.run (test_server default_prefs)
