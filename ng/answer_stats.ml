(* see https://github.com/avsm/ocaml-cohttpserver/blob/master/server/http_tcp_server.ml *)

open Lwt

open LwtParsingEngine
open AnswerDump
open Tls

let handle_error = function
  | End_of_file -> return ()
  | _ -> print_char 'E'; return ()

let rec read_messages input () =
  lwt_parse_tls_record input >>= fun _record ->
  print_char '.';
  read_messages input ()

let rec read_answer input () =
  lwt_parse_answer_dump input >>= fun answer ->
  print_string (PrintingEngine.print_ipv4 "" "IP" answer.ip);
  let answer_input = input_of_channel "Answer" (Lwt_io.of_bytes ~mode:Lwt_io.input (Lwt_bytes.of_string answer.content)) in
  catch (read_messages answer_input) handle_error >>= fun () ->
  read_answer input ()

let ignore_eof = function
  | End_of_file -> return ()
  | e -> fail e

let _ =
  let t = read_answer (input_of_fd "(stdin)" Lwt_unix.stdin) in
  Lwt_unix.run (catch t ignore_eof)
