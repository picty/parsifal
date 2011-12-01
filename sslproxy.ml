(* see https://github.com/avsm/ocaml-cohttpserver/blob/master/server/http_tcp_server.ml *)

open Lwt
open Unix

(* TODO: Handle Unix exceptions *)


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



let rec forward i o =
  let s = String.create 16 in
  Lwt_unix.read i s 0 16 >>= fun l ->
  if l > 0 then begin
    print_endline (Common.hexdump s);
    really_write o s 0 l >>= fun () ->
    forward i o
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
     let io = forward inp out in
     let oi = forward out inp in
     io >>= fun () -> oi >>= fun () ->
     Lwt_unix.close out;
     Lwt_unix.close inp;
     Lwt.return ());
  accept sock

let _ =
  let socket = new_socket () in
  Lwt_unix.setsockopt
  socket Unix.SO_REUSEADDR true;
  Lwt_unix.bind socket local_addr;
  Lwt_unix.listen socket 1024;
  Lwt_unix.run (accept socket)
