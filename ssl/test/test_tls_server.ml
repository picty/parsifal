open Parsifal
open Lwt
open Tls
open TlsEngineNG

let test_server prefs =
  let ctx = empty_context prefs in
  init_server_connection 1234 >>=
  accept_client >>= fun c_sock ->
  run_automata server_automata ServerNil "" ctx c_sock >>= fun _ ->
  Lwt_unix.close c_sock.socket

let _ =
  try
    TlsDatabase.enrich_suite_hash ();
    Unix.handle_unix_error Lwt_main.run (test_server (default_prefs DummyRNG))
  with
    | ParsingException (e, h) -> prerr_endline (string_of_exception e h); exit 1
    | e -> prerr_endline (Printexc.to_string e)
