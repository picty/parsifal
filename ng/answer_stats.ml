(* see https://github.com/avsm/ocaml-cohttpserver/blob/master/server/http_tcp_server.ml *)

open Lwt

open LwtParsingEngine
open AnswerDump


let rec read_answer input () =
  lwt_parse_answer_dump input >>= fun answer ->
  print_string (PrintingEngine.print_ipv4 "" "IP" answer.ip);
  read_answer input ()

let ignore_eof = function
  | End_of_file -> return ()
  | e -> fail e

let _ =
  let t = read_answer (input_of_fd "(stdin)" Lwt_unix.stdin) in
  Lwt_unix.run (catch t ignore_eof)
