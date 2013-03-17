open Lwt
open Lwt_unix
open Sys
open Parsifal
open TlsEnums
open Tls

let do_stg () =
  Lwt_unix.openfile Sys.argv.(1) [O_RDONLY] 0o640 >>= fun fd ->
  input_of_fd "TLS Record" fd >>= fun input ->
  enrich_record_content := true;
  lwt_parse_tls_record None input >>= fun tls_record ->
  Lwt_io.printf "%s" (print_value (value_of_tls_record tls_record)) >>= fun () ->
  let res = dump_tls_record tls_record in
  wrap1 (parse_tls_record None) (input_of_string "" res) >>= fun tls_record2 ->
  if res = dump_tls_record tls_record2
  then return (hexdump res)
  else fail (Failure "dump (parse (res)) is not idempotent")

let catcher = function
  | ParsingException (e, h) -> return (string_of_exception e h)
  | e -> return (Printexc.to_string e)


let main = catch do_stg catcher

let _ =
  print_endline (Lwt_main.run main)

