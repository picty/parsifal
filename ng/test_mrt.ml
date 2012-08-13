open Common
open Lwt
open Mrt
open ParsingEngine
open LwtParsingEngine

let rec handle_one_file input =
  lwt_parse_mrt_message input >>= fun mrt_msg ->
  print_endline (print_mrt_message "" "Message" mrt_msg);
  handle_one_file input

let _ =
  try
    Lwt_unix.run (handle_one_file (LwtParsingEngine.input_of_channel "(stdin)" Lwt_io.stdin));
  with
    | End_of_file -> ()
    | ParsingException (e, i) -> emit_parsing_exception false e i
    | LwtParsingException (e, i) -> emit_lwt_parsing_exception false e i
    | e -> print_endline (Printexc.to_string e)

