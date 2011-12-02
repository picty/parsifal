(* see https://github.com/avsm/ocaml-cohttpserver/blob/master/server/http_tcp_server.ml *)

open Lwt
open Unix

(* TODO: Handle Unix exceptions *)



type tls_state = {
  name : string;

  mutable clear : bool;
  mutable cur_buf : string;
  mutable cur_records : TlsRecord.RecordParser.t list;
}

let empty_state name =
  { name = name; clear = true;
    cur_buf = ""; cur_records = [] }



(* write l bytes of string s
 * starting at position p to file descriptor o.
 * Several calls to function Lwt_unix.write may
 * be needed as the system call may write less
 * than l bytes.
 *)
let rec really_write o s p l =
  Lwt_unix.write o s p l >>= fun n ->
  if l = n then
    Lwt.return ()
  else
    really_write o s (p + n) (l - n)


let parse_records s =
  let pstate = ParsingEngine.pstate_of_string None s.cur_buf in

  let rec aux accu =
    let saved_pstate = ParsingEngine.clone_pstate pstate in
    try
      let record = TlsRecord.RecordParser.parse pstate in
      aux (record::accu)
    with ParsingEngine.OutOfBounds _ ->
      s.cur_buf <- ParsingEngine.pop_string saved_pstate;
      s.cur_records <- List.rev accu
  in
  aux (List.rev s.cur_records)



let write_record o record =
  let s = TlsRecord.RecordParser.dump record in
  let l = String.length s in
  really_write o s 0 l

let print_record name record =
  print_endline name;
  print_endline (String.concat "\n" (List.map (fun s -> "  " ^ s) (TlsRecord.RecordParser.to_string record)));
  print_newline ()

let handle_records state =
  let rec aux deep_parsed ready_to_go pending rest =
    match state.clear, pending, rest with
      | _, p, [] -> List.rev deep_parsed, List.rev ready_to_go, List.rev pending
      | false, [], r::rem -> aux (r::deep_parsed) (r::ready_to_go) [] rem
      | false, _, _ -> failwith "This should not happen"
      | true, p, r::rem ->
	try
	  let parsed_recs = Tls.TlsLib._deep_parse_aux state.name (List.rev (r::p)) false in
	  if r.TlsRecord.content_type == 20
	  then state.clear <- false;
	  aux (List.rev_append parsed_recs deep_parsed) (r::(p@ready_to_go)) [] rem
	with _ -> aux deep_parsed ready_to_go (r::p) rest
  in
  let deep_parsed, ready_to_go, still_unparsed = aux [] [] [] state.cur_records in
  List.iter (print_record state.name) deep_parsed;
  state.cur_records <- still_unparsed;
  ready_to_go


let rec forward state i o =
  let new_buf = String.make 1024 ' ' in
  Lwt_unix.read i new_buf 0 1024 >>= fun l ->
  if l > 0 then begin
    state.cur_buf <- state.cur_buf ^ (String.sub new_buf 0 l);
    parse_records state;
    let records = handle_records state in
    (Lwt_list.iter_s (write_record o) records) >>= fun () ->
    forward state i o
  end else begin
    Lwt_unix.shutdown o Unix.SHUTDOWN_SEND;
    Lwt.return ()
  end


let new_socket () =
  Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0
let local_addr =
  Unix.ADDR_INET (Unix.inet_addr_any, 8080)
let remote_addr =
  let host_entry = Unix.gethostbyname "www.google.com" in
  let inet_addr = host_entry.Unix.h_addr_list.(0) in
  Unix.ADDR_INET (inet_addr, 443)

(* Start two threads to forward both input and output,
 * and wait for both threads to end.
 * Close file descriptors and exit
 *)
let rec accept sock =
  Lwt_unix.accept sock >>= fun (inp, _) ->
  ignore
    (let out = new_socket () in
     Lwt_unix.connect out remote_addr >>= fun () ->
     let io = forward (empty_state "C->S") inp out in
     let oi = forward (empty_state "S->C") out inp in
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
