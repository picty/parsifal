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
  Printf.printf "  Content length: %d\n" (String.length tls_record.record_content);
  if tls_record.content_type = RT_Handshake then begin
    let hs_msg = parse_handshake_msg (input_of_string "Handshake" tls_record.record_content) in
    Printf.printf "    Handshake message type: %s\n" (string_of_hs_message_type hs_msg.handshake_type);
    Printf.printf "    Handshake content length: %d\n" (String.length hs_msg.handshake_content);
  end;
  if dump_tls_record tls_record = s
  then print_endline "Yes!"
  else print_endline "NO!"
