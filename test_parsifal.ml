open Parsifal

enum tls_version [with_lwt] (16, UnknownVal V_Unknown) =
  | 0x0002 -> V_SSLv2, "SSLv2"
  | 0x0300 -> V_SSLv3, "SSLv3"
  | 0x0301 -> V_TLSv1, "TLSv1.0"
  | 0x0302 -> V_TLSv1_1, "TLSv1.1"
  | 0x0303 -> V_TLSv1_2, "TLSv1.2"

enum tls_version_bis (16, Exception E_Unknown) =
  | 0x0002 -> V_SSLv2, "SSLv2"
  | 0x0300 -> V_SSLv3, "SSLv3"
  | 0x0301 -> V_TLSv1, "TLSv1.0"
  | 0x0302 -> V_TLSv1_1, "TLSv1.1"
  | 0x0303 -> V_TLSv1_2, "TLSv1.2"

struct st [top] = {
  x : uint8;
  y : string(x);
  len : uint8;
  l : list(len) of uint16
}

struct st2 [top] = {
  l : uint8;
  a : array(l) of uint16
}

alias l1 [top] = list of st

struct rsa_public_key_content = {
  p_modulus : Asn1PTypes.der_integer;
  p_publicExponent : Asn1PTypes.der_integer
}

asn1_alias rsa_public_key [with_exact]


let test parse dump print name s =
  try
    let x = parse (input_of_string "" s) in
    print_endline (print x);
    if (dump x = s)
    then Printf.printf "Parse/Dump is idempotent for %s\n" name
    else Printf.printf "Parse/Dump is NOT idempotent for %s\n" name
  with ParsingException (e, StringInput i) ->
    Printf.printf "test failed for %s: %s in %s\n" name
      (print_parsing_exception e) (print_string_input i)

let test_st = test exact_parse_st dump_st print_st "st"
let test_st2 = test exact_parse_st2 dump_st2 print_st2 "st2"
let test_l1 = test exact_parse_l1 dump_l1 print_l1 "l1"
let test_rsa = test exact_parse_rsa_public_key dump_rsa_public_key print_rsa_public_key "rsa_public_key"

let _ =
  print_endline (string_of_tls_version (tls_version_of_int 768));
  print_endline (string_of_tls_version_bis (tls_version_bis_of_int 768));
  test_st "\x04toto\x02AA";
  test_st "\x04toto\x02AABB";
  test_st "\x04toto\x02AABBCC";
  test_st2 "\x02AABB";
  test_st2 "\x03AABBCC";
  test_st2 "\x02";
  test_l1 "\x04toto\x02AABB\x02yo\x00";
  test_rsa "\x30\x0d\x02\x08AABBCCDD\x02\x01\x03";
  ()
