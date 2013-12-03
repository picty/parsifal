open Lwt
open LwtUtil
open Unix

open Parsifal
open TlsEnums
open Tls
open Getopt


let host = ref "www.google.com"
let port = ref 443
let max_client_bytes = ref 88
let output_name = ref ""
let dirty = ref false
let timeout = ref 10.0
let proba = ref 0.75

let output_file = ref Pervasives.stdout

let options = [
  mkopt (Some 'h') "help" Usage "show this help";

  mkopt (Some 't') "timeout" (FloatVal timeout) "set the timeout";
  mkopt (Some 'D') "dirty" (Set dirty) "break client connections by closing the socket";
  mkopt (Some 'o') "output" (StringVal output_name) "Output file to put ciphertexts in";
  mkopt (Some 'm') "max-client-bytes" (IntVal max_client_bytes) "Sets the maximum size of C->S ciphertext allowed";
  mkopt (Some 'H') "host" (StringVal host) "host to contact";
  mkopt (Some 'p') "port" (IntVal port) "port to probe";
  mkopt None "proba" (FloatVal proba) "set the proba to cut the connection after max-client-bytes";
]



type tls_state = {
  name : string;
  blork : bool;
  mutable clear : bool;
  mutable appdata : string;
}

let empty_state name =
  { name = name; blork = Random.float 1. < !proba; clear = true; appdata = "" }

let output_appdata state =
  let appdata = String.sub state.appdata 0 (min (String.length state.appdata) 100) in
  output_string !output_file (Printf.sprintf "%0.0f %s\n" (Unix.time ()) (hexdump appdata));
  flush !output_file


let update_appdata max state s =
  state.appdata <- state.appdata ^ s;
  if state.blork && String.length state.appdata >= max
  then begin
    output_appdata state;
    Some "\x15\x03\x05\x00\x00"
  end else None

let handle_timeout state =
  Lwt_unix.sleep !timeout >>= fun () ->
  output_appdata state;
  fail (Failure "Timeout")


let dumb_update _ _ = None


let rec _really_write o s p l =
  Lwt_unix.write o s p l >>= fun n ->
  if l = n then
    Lwt.return ()
  else
    _really_write o s (p + n) (l - n)

let really_write o s = _really_write o s 0 (String.length s)


let write_record o record =
  let s = exact_dump_tls_record record in
  really_write o s


let rec forward update_fun state i o =
  lwt_parse_wrapper (parse_tls_record None) i >>= fun record ->
(*   print_string (print_value ~name:state.name (value_of_tls_record record)); *)
  write_record o record >>= fun () ->
  begin
    match record.content_type, state.clear with
    | CT_ChangeCipherSpec, true ->
      state.clear <- false;
      return ()
    | CT_ApplicationData, false ->
      let new_bytes = exact_dump_record_content record.record_content in begin
	match update_fun state new_bytes with
	| None -> return ()
	| Some s -> if !dirty then fail (Failure "Blork!") else really_write o s
      end
      | _ -> return ()
  end >>= fun () ->
  forward update_fun state i o


let catcher = function
  | ParsingException (e, h) ->
    Lwt_io.write_line Lwt_io.stderr (string_of_exception e h)
  | e ->
    Lwt_io.write_line Lwt_io.stderr (Printexc.to_string e)


let rec accept sock =
  Lwt_unix.accept sock >>= fun (inp, _) ->
  LwtUtil.client_socket !host !port >>= fun out ->
  input_of_fd "Client socket" inp >>= fun i ->
  input_of_fd "Server socket" out >>= fun o ->
  Lwt_io.write_line Lwt_io.stderr "Connection accepted" >>= fun () ->
  let client_state = empty_state "C->S" in
  let io = forward (update_appdata !max_client_bytes) client_state i out in
  let oi = forward dumb_update (empty_state "S->C") o inp in
  let client =
    catch (fun () -> pick [io; oi; handle_timeout client_state]) catcher >>= fun () ->
    Lwt_unix.close out >>= fun () ->
    Lwt_unix.close inp
  in
  join [client; accept sock]

let _ =
  let _ = parse_args ~progname:"disturber" options Sys.argv in
  if !output_name <> "" then output_file := open_out !output_name;
  let socket = LwtUtil.server_socket 8000in
  Lwt_unix.run (accept socket)
