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

let test_st s =
  try
    print_endline (print_st (exact_parse_st (input_of_string "" s)))
  with ParsingException (e, StringInput i) -> emit_parsing_exception false e i

let _ =
  print_endline (string_of_tls_version (tls_version_of_int 768));
  print_endline (string_of_tls_version_bis (tls_version_bis_of_int 768));
  test_st "\x04toto\x02AA";
  test_st "\x04toto\x02AABB";
  test_st "\x04toto\x02AABBCC"
