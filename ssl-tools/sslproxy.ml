open Lwt
open LwtUtil
open Unix

open Parsifal
open TlsEnums
open Tls
open Getopt


let host = ref "www.google.com"
let port = ref 443

let options = [
  mkopt (Some 'h') "help" Usage "show this help";

  mkopt (Some 'H') "host" (StringVal host) "host to contact";
  mkopt (Some 'p') "port" (IntVal port) "port to probe";
]



(* TODO: Handle exceptions in lwt code, and add timers *)


type tls_state = {
  name : string;
  mutable clear : bool;
}

let empty_state name =
  { name = name; clear = true }



let write_record o record =
  let s = exact_dump_tls_record record in
  really_write o s


let rec forward state i o =
  let opts = incr_indent default_output_options in
  lwt_parse_wrapper (parse_tls_record None) i >>= fun record ->
  print_string (print_value ~name:state.name (value_of_tls_record record));
  write_record o record >>= fun () ->
  try
    begin
      match record.content_type, state.clear with
      | CT_Handshake, true ->
	let hs_msg = parse_handshake_msg None (input_of_string "Handshake" (exact_dump_record_content record.record_content)) in
	print_endline (print_value ~options:opts ~name:"Handshake content" (value_of_handshake_msg hs_msg))
      | CT_ChangeCipherSpec, true ->
	let hs_msg = parse_change_cipher_spec (input_of_string "CCS" (exact_dump_record_content record.record_content)) in
	print_endline (print_value ~options:opts ~name:"CCS content" (value_of_change_cipher_spec hs_msg));
	state.clear <- false
      | CT_Alert, true ->
	let hs_msg = parse_tls_alert (input_of_string "Alert" (exact_dump_record_content record.record_content)) in
	print_endline (print_value ~options:opts ~name:"Alert content" (value_of_tls_alert hs_msg))
      | _ -> print_newline ()
    end;
    forward state i o
  with e -> fail e


let catcher = function
  | ParsingException (e, h) ->
    Lwt_io.write_line Lwt_io.stderr (string_of_exception e h)
  | e ->
    Lwt_io.write_line Lwt_io.stderr (Printexc.to_string e)



let rec accept sock =
  Lwt_unix.accept sock >>= fun (inp, remote_s) ->
  let p = match remote_s with
    | ADDR_INET (_, p) -> p
    | _ -> 0
  in
  LwtUtil.client_socket !host !port >>= fun out ->
  input_of_fd "Client socket" inp >>= fun i ->
  input_of_fd "Server socket" out >>= fun o ->
  let io = forward (empty_state (Printf.sprintf "%4.4x C->S" p)) i out in
  let oi = forward (empty_state (Printf.sprintf "%4.4x S->C" p)) o inp in
  catch (fun () -> pick [io; oi]) catcher >>= fun () ->
  ignore (Lwt_unix.close out);
  ignore (Lwt_unix.close inp);
  accept sock

let _ =
  let _ = parse_args ~progname:"sslproxy" options Sys.argv in
  let socket = LwtUtil.server_socket 8080 in
  Lwt_unix.run (accept socket)
