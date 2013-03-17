open Parsifal
open Asn1PTypes

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

asn1_union der_time [top; enrich; exhaustive] (UnparsedTime) =
  | (Asn1Engine.C_Universal, false, Asn1Engine.T_UTCTime) -> UTCTime of Asn1PTypes.der_utc_time_content
  | (Asn1Engine.C_Universal, false, Asn1Engine.T_GeneralizedTime) -> GeneralizedTime of Asn1PTypes.der_generalized_time_content


let test (parse : string_input -> 'a)
         (dump : 'a -> string)
	 (value_of : 'a -> value)
	 (name : string) (s : string) =
  try
    let x = parse (input_of_string "" s) in
    print_endline (print_value ~name:name (value_of x));
    if (dump x = s)
    then Printf.printf "Parse/Dump is idempotent for %s\n" name
    else Printf.printf "Parse/Dump is NOT idempotent for %s\n" name
  with ParsingException (e, h) ->
    Printf.printf "test failed for %s: %s\n" name (string_of_exception e h)


let test_st = test exact_parse_st dump_st value_of_st "st"
let test_st2 = test exact_parse_st2 dump_st2 value_of_st2 "st2"
let test_l1 = test exact_parse_l1 dump_l1 value_of_l1 "l1"
let test_rsa = test exact_parse_rsa_public_key dump_rsa_public_key value_of_rsa_public_key "rsa_public_key"
let test_der_object = test parse_der_object dump_der_object value_of_der_object "der_object"

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
  test_der_object "\x30\x0d\x02\x08AABBCCDD\x02\x01\x03";
  for i = 1 to (Array.length Sys.argv) - 1 do
    match get (value_of_st (parse_st (input_of_string "" "\x04toto\x02AABB"))) Sys.argv.(i) with
    | Left e -> Printf.printf "Left \"%s\"\n" e
    | Right s -> Printf.printf "Right %s\n" s
  done;
  ()
