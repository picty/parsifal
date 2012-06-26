open Sys
open ParsingEngine
open Common
open RSAPrivateKey

let _ =
  let s = get_file_content Sys.argv.(1) in
  let input = input_of_string "TLS Record" s in
  let rsa_key = parse_rsa_private_key input in
  print_endline (hexdump rsa_key.modulus)

