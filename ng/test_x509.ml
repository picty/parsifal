open Unix
open Sys
open Common
open ParsingEngine
open X509

let get_file_content filename =
  let f = open_in filename in
  let fd = descr_of_in_channel f in
  let stats = fstat fd in
  let len = stats.st_size in
  let res = String.make len ' ' in
  really_input f res 0 len;
  res

let _ =
  try
    let s = get_file_content Sys.argv.(1) in
    let input = input_of_string ("\"" ^ Sys.argv.(1) ^ "\"") s in
    let certificate = parse_certificate input in
    print_endline (hexdump certificate.tbsCertificate.serialNumber)
  with
  | ParsingException (e, i) -> emit_parsing_exception false e i
  | Asn1Engine.Asn1Exception (e, i) -> Asn1Engine.emit false e i

