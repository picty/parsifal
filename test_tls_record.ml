open Lwt
open Lwt_unix
open Sys
open ParsingEngine
open LwtParsingEngine
open TlsEnums
open Tls

let do_stg () =
  Lwt_unix.openfile Sys.argv.(1) [O_RDONLY] 0o640 >>= fun fd ->
  let input = input_of_fd "TLS Record" fd in
  enrich_record_content := true;
  lwt_parse_tls_record None input >>= fun tls_record ->
  Lwt_io.printf "%s" (print_tls_record tls_record) >>= fun () ->
  let res = dump_tls_record tls_record in
  wrap1 (parse_tls_record None) (input_of_string "" res) >>= fun tls_record2 ->
  if res = dump_tls_record tls_record2
  then return (Common.hexdump res)
  else fail (Failure "dump (parse (res)) is not idempotent")

let catcher = function
  | ParsingException (e, i) ->
    return (Printf.sprintf "%s in %s" (ParsingEngine.print_parsing_exception e)
	      (ParsingEngine.print_string_input i))
  | e -> return (Printexc.to_string e)


let main = catch do_stg catcher

let _ =
  print_endline (Lwt_main.run main)

