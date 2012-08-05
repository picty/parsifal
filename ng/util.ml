open Lwt

exception Timeout

let client_socket ?timeout:(timeout=None) host port =
  let s = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  let host_entry = Unix.gethostbyname host in
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
