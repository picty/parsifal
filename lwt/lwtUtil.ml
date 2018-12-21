open Parsifal
open Lwt

let rec _really_write o s p l =
  Lwt_unix.write o s p l >>= fun n ->
  if l = n then
    Lwt.return ()
  else
    _really_write o s (p + n) (l - n)

let really_write o s = _really_write o (Bytes.of_string s) 0 (String.length s)



exception Timeout

let client_socket ?timeout:(timeout=None) host port =
  let s = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  Lwt_unix.gethostbyname host >>= fun host_entry ->
  let inet_addr = host_entry.Unix.h_addr_list.(0) in
  let addr = Unix.ADDR_INET (inet_addr, port) in
  let t = Lwt_unix.connect s addr in
  let timed_t = match timeout with
    | None -> t
    | Some timeout_val ->
      pick [t; Lwt_unix.sleep timeout_val >>= fun () -> fail Timeout]
  in timed_t >>= fun () -> return s

let server_socket ?bind_address:(bind_addr=None) ?backlog:(backlog=1024) port =
  let s = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  let inet_addr = match bind_addr with
    | Some a -> Unix.inet_addr_of_string a
    | None -> Unix.inet_addr_any
  in
  let local_addr = Unix.ADDR_INET (inet_addr, port) in
  Lwt_unix.setsockopt s Unix.SO_REUSEADDR true;
  Lwt_unix.bind s local_addr;
  Lwt_unix.listen s backlog;
  s

let launch_server ?bind_address:(bind_addr=None) ?backlog:(backlog=1024) port (service : Lwt_unix.file_descr -> unit Lwt.t) =
  let s_socket = server_socket ~bind_address:bind_addr ~backlog:backlog port in
  let rec do_accept () =
    Lwt_unix.accept s_socket >>= fun (s, _) ->
    service s >>= fun () ->
    do_accept ()
  in
  Lwt_unix.run (do_accept ())






(**********************************)
(* TODO: Work on this sordid hack *)
(**********************************)

(* In particular, this does NOT work with parse_rem_* stuff... *)
type lwt_input = {
  lwt_ch : Lwt_io.input_channel;
  mutable lwt_eof : bool;
  mutable string_input : string_input;
}

let input_of_channel ?verbose:(verbose=true) ?enrich:(enrich=DefaultEnrich) name ch =
  let string_input = input_of_string ~verbose:verbose ~enrich:enrich name "" in
  return { lwt_ch = ch;
	   lwt_eof = false;
	   string_input = string_input }

let input_of_fd ?verbose:(verbose=true) ?enrich:(enrich=DefaultEnrich) name fd =
  let ch = Lwt_io.of_fd Lwt_io.input fd in
  input_of_channel ~verbose:verbose ~enrich:enrich name ch

let input_of_filename ?verbose:(verbose=true) ?enrich:(enrich=DefaultEnrich) filename =
  Lwt_unix.openfile filename [Unix.O_RDONLY] 0 >>= fun fd ->
  input_of_fd ~verbose:verbose ~enrich:enrich filename fd


(* TODO: use a flavour of try_parse that only catches OOB exceptions? *)
let lwt_parse_wrapper parse_fun lwt_input =
  let rec try_str_parse () =
    if lwt_input.lwt_eof
    then Lwt.wrap1 parse_fun lwt_input.string_input
    else match try_parse parse_fun lwt_input.string_input with
    | None ->
      let buf = Bytes.create 8192 in
      Lwt_io.read_into lwt_input.lwt_ch buf 0 8192 >>= fun n_read ->
      if n_read == 0
      then lwt_input.lwt_eof <- true
      else begin
	let new_string_input = append_to_input lwt_input.string_input (Bytes.sub_string buf 0 n_read) in
	lwt_input.string_input <- new_string_input
      end;
      try_str_parse ()
    | Some x ->
	let new_string_input = drop_used_string lwt_input.string_input in
	lwt_input.string_input <- new_string_input;
	return x
  in try_str_parse ()
(*****************************)  
