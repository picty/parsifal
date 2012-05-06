open Sys
open ParsingEngine
open Common
open TlsEnums
open Tls

let _ =
  let s = get_file_content Sys.argv.(1) in
  let input = input_of_string "TLS Record" s in
  let tls_record = parse_tls_record input in
  Printf.printf "TLS Record\n";
  Printf.printf "  Content type: %s\n" (string_of_tls_content_type tls_record.content_type);
  Printf.printf "  Version: %s\n" (string_of_tls_version tls_record.record_version);
  Printf.printf "  Content length: %d\n" (String.length tls_record.content);
  if dump_tls_record tls_record = s
  then print_endline "Yes!"
  else print_endline "NO!"
