(* ocamlc -pp "camlp4o ./preprocess_camlp4.cmo" mk_enum_camlp4_test.ml *)

enum tls_version = [
  0x0002, V_SSLv2, "SSLv2";
  0x0300, V_SSLv3, "SSLv3";
  0x0301, V_TLSv1, "TLSv1.0";
  0x0302, V_TLSv1_1, "TLSv1.1";
  0x0303, V_TLSv1_2, "TLSv1.2";
], [UnknownVal V_Unknown]

let _ =
  print_endline (string_of_tls_version (tls_version_of_int 768));
