(*
   ocamlc -pp "camlp4o pa_extend.cmo pa_macro.cmo q_MLast.cmo" -I /usr/lib/ocaml/camlp4 -c mk_enum_camlp4.ml &&
   camlp4o mk_enum_camlp4.cmo mk_enum_camlp4_test.ml &&
   ocamlc -I .. -I /usr/lib/ocaml/lwt -pp "camlp4o mk_enum_camlp4.cmo" lwt.cma ../common.ml ../printingEngine.ml mk_enum_camlp4_test.ml &&
   ./a.out
*)

enum tls_version = [
  0x0002, V_SSLv2, "SSLv2";
  0x0300, V_SSLv3, "SSLv3";
  0x0301, V_TLSv1, "TLSv1.0";
  0x0302, V_TLSv1_1, "TLSv1.1";
  0x0303, V_TLSv1_2, "TLSv1.2";
], [UnknownVal V_Unknown], [lwt]

enum tls_version_bis = [
  0x0002, VV_SSLv2, "SSLv2";
  0x0300, VV_SSLv3, "SSLv3";
  0x0301, VV_TLSv1, "TLSv1.0";
  0x0302, VV_TLSv1_1, "TLSv1.1";
  0x0303, VV_TLSv1_2, "TLSv1.2";
], [Exception E_Unknown], []

let _ =
  print_endline (string_of_tls_version (tls_version_of_int 768));
  print_endline (string_of_tls_version_bis (tls_version_bis_of_int 768));
