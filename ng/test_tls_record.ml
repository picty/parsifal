open Sys
open ParsingEngine
open Common
open TlsEnums
open Tls

let _ =
  let s = get_file_content Sys.argv.(1) in
  let input = input_of_string "TLS Record" s in
  let tls_record = parse_tls_record input in
  print_endline (print_tls_record "" "TLS_Record" tls_record);
  if tls_record.content_type = CT_Handshake then begin
    let hs_msg = parse_handshake_msg (input_of_string "Handshake" tls_record.record_content) in
    print_endline (print_handshake_msg "  " "Handshake message" hs_msg)
  end;
  if dump_tls_record tls_record = s
  then print_endline "Yes!"
  else print_endline "NO!";

