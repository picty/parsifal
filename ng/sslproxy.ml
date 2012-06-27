(* see https://github.com/avsm/ocaml-cohttpserver/blob/master/server/http_tcp_server.ml *)

open Lwt
open Unix

open ParsingEngine
open DumpingEngine
open LwtParsingEngine
open TlsEnums
open Tls


(* TODO: Handle exceptions in lwt code, and add timers *)


type tls_state = {
  name : string;
  mutable clear : bool;
}

let empty_state name =
  { name = name; clear = true }


let rec _really_write o s p l =
  Lwt_unix.write o s p l >>= fun n ->
  if l = n then
    Lwt.return ()
  else
    _really_write o s (p + n) (l - n)

let really_write o s = _really_write o s 0 (String.length s)


let write_record o record =
  let s = dump_tls_record record in
  really_write o s


let rec forward state i o =
  lwt_parse_tls_record i >>= fun record ->
  print_string (print_tls_record "" state.name record);
  write_record o record >>= fun () ->
  begin
    match record.content_type, state.clear with
      | CT_Handshake, true ->
	let hs_msg = parse_handshake_msg (input_of_string "Handshake" (dump_record_content record.record_content)) in
	print_endline (print_handshake_msg "  " "Handshake content" hs_msg)
      | CT_ChangeCipherSpec, true ->
	let hs_msg = parse_change_cipher_spec (input_of_string "CCS" (dump_record_content record.record_content)) in
	print_endline (print_change_cipher_spec "  " "CCS content" hs_msg);
	state.clear <- false
      | CT_Alert, true ->
	let hs_msg = parse_tls_alert (input_of_string "Alert" (dump_record_content record.record_content)) in
	print_endline (print_tls_alert "  " "Alert content" hs_msg)
      | _ -> print_newline ()
  end;
  forward state i o


let new_socket () =
  Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0
let local_addr =
  Unix.ADDR_INET (Unix.inet_addr_any, 8080)
let remote_addr =
  let host_entry = Unix.gethostbyname "www.google.com" in
  let inet_addr = host_entry.Unix.h_addr_list.(0) in
  Unix.ADDR_INET (inet_addr, 443)

let rec accept sock =
  Lwt_unix.accept sock >>= fun (inp, _) ->
  ignore
    (let out = new_socket () in
     Lwt_unix.connect out remote_addr >>= fun () ->
     let io = forward (empty_state "C->S") (input_of_fd "Client socket" inp) out in
     let oi = forward (empty_state "S->C") (input_of_fd "Server socket" out) inp in
     io >>= fun () -> oi >>= fun () ->
     ignore (Lwt_unix.close out);
     ignore (Lwt_unix.close inp);
     Lwt.return ());
  accept sock

let _ =
  let socket = new_socket () in
  Lwt_unix.setsockopt
  socket Unix.SO_REUSEADDR true;
  Lwt_unix.bind socket local_addr;
  Lwt_unix.listen socket 1024;
  Lwt_unix.run (accept socket)
