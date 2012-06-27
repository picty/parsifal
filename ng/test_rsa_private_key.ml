open Unix
open Sys
open Common
open ParsingEngine
open RSAPrivateKey

let get_file_content filename =
  let f = open_in filename in
  let fd = descr_of_in_channel f in
  let stats = fstat fd in
  let len = stats.st_size in
  let res = String.make len ' ' in
  really_input f res 0 len;
  res

let _ =
  let s = get_file_content Sys.argv.(1) in
  let input = input_of_string "TLS Record" s in
  let rsa_key = parse_rsa_private_key input in
  print_endline (hexdump rsa_key.modulus)

