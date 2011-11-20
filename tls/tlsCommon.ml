open Common
open Types
open ParsingEngine

(* Protocol version *)

type protocol_version = int

let protocol_version_string_of_int = function
  | 0x0200 -> "SSLv2"
  | 0x0300 -> "SSLv3"
  | 0x0301 -> "TLSv1.0"
  | 0x0302 -> "TLSv1.1"
  | 0x0303 -> "TLSv1.2"
  | v -> (string_of_int (v lsr 8)) ^ "." ^ (string_of_int (v land 0xff))

let protocol_version_int_of_string = function
  | "SSLv2" -> 0x0200
  | "SSLv3" -> 0x0300
  | "TLSv1.0" -> 0x0301
  | "TLSv1.1" -> 0x0302
  | "TLSv1.2" -> 0x0303
  | s -> match string_split '.' s with
      | [maj; min] -> ((int_of_string maj) lsl 8) lor (int_of_string min)
      | _ -> raise (ContentError "Invalid protocol version")

let parse_protocol_version pstate =
  let v = pop_uint16 pstate in
  V_Enumerated (v, protocol_version_string_of_int)

let _make_protocol_version = function
  | V_Int i
  | V_Enumerated (i, _) -> i
  | V_String s -> protocol_version_int_of_string s
  | _ -> raise (ContentError "Invalid protocol version value")

let make_protocol_version v = V_Enumerated (_make_protocol_version v, protocol_version_string_of_int)



(* Cipher suite *)

type cipher_suite = int

let cipher_suite_strings = [
  (0x0000, "NULL_WITH_NULL_NULL");
  (0x0001, "RSA_WITH_NULL_MD5");
  (0x0002, "RSA_WITH_NULL_SHA");
  (0x0003, "RSA_EXPORT_WITH_RC4_40_MD5");
  (0x0004, "RSA_WITH_RC4_128_MD5");
  (0x0005, "RSA_WITH_RC4_128_SHA");
  (0x0006, "RSA_EXPORT_WITH_RC2_CBC_40_MD5");
  (0x0007, "RSA_WITH_IDEA_CBC_SHA");
  (0x0008, "RSA_EXPORT_WITH_DES40_CBC_SHA");
  (0x0009, "RSA_WITH_DES_CBC_SHA");
  (0x000a, "RSA_WITH_3DES_EDE_CBC_SHA");
  (0x000b, "DH_DSS_EXPORT_WITH_DES40_CBC_SHA");
  (0x000c, "DH_DSS_WITH_DES_CBC_SHA");
  (0x000d, "DH_DSS_WITH_3DES_EDE_CBC_SHA");
  (0x000e, "DH_RSA_EXPORT_WITH_DES40_CBC_SHA");
  (0x000f, "DH_RSA_WITH_DES_CBC_SHA");
  (0x0010, "DH_RSA_WITH_3DES_EDE_CBC_SHA");
  (0x0011, "DHE_DSS_EXPORT_WITH_DES40_CBC_SHA");
  (0x0012, "DHE_DSS_WITH_DES_CBC_SHA");
  (0x0013, "DHE_DSS_WITH_3DES_EDE_CBC_SHA");
  (0x0014, "DHE_RSA_EXPORT_WITH_DES40_CBC_SHA");
  (0x0015, "DHE_RSA_WITH_DES_CBC_SHA");
  (0x0016, "DHE_RSA_WITH_3DES_EDE_CBC_SHA");
  (0x0017, "DH_anon_EXPORT_WITH_RC4_40_MD5");
  (0x0018, "DH_anon_WITH_RC4_128_MD5");
  (0x0019, "DH_anon_EXPORT_WITH_DES40_CBC_SHA");
  (0x001a, "DH_anon_WITH_DES_CBC_SHA");
  (0x001b, "DH_anon_WITH_3DES_EDE_CBC_SHA");
  (0x001e, "KRB5_WITH_DES_CBC_SHA");
  (0x001f, "KRB5_WITH_3DES_EDE_CBC_SHA");
  (0x0020, "KRB5_WITH_RC4_128_SHA");
  (0x0021, "KRB5_WITH_IDEA_CBC_SHA");
  (0x0022, "KRB5_WITH_DES_CBC_MD5");
  (0x0023, "KRB5_WITH_3DES_EDE_CBC_MD5");
  (0x0024, "KRB5_WITH_RC4_128_MD5");
  (0x0025, "KRB5_WITH_IDEA_CBC_MD5");
  (0x0026, "KRB5_EXPORT_WITH_DES_CBC_40_SHA");
  (0x0027, "KRB5_EXPORT_WITH_RC2_CBC_40_SHA");
  (0x0028, "KRB5_EXPORT_WITH_RC4_40_SHA");
  (0x0029, "KRB5_EXPORT_WITH_DES_CBC_40_MD5");
  (0x002a, "KRB5_EXPORT_WITH_RC2_CBC_40_MD5");
  (0x002b, "KRB5_EXPORT_WITH_RC4_40_MD5");
  (0x002c, "PSK_WITH_NULL_SHA");
  (0x002d, "DHE_PSK_WITH_NULL_SHA");
  (0x002e, "RSA_PSK_WITH_NULL_SHA");
  (0x002f, "RSA_WITH_AES_128_CBC_SHA");
  (0x0030, "DH_DSS_WITH_AES_128_CBC_SHA");
  (0x0031, "DH_RSA_WITH_AES_128_CBC_SHA");
  (0x0032, "DHE_DSS_WITH_AES_128_CBC_SHA");
  (0x0033, "DHE_RSA_WITH_AES_128_CBC_SHA");
  (0x0034, "DH_anon_WITH_AES_128_CBC_SHA");
  (0x0035, "RSA_WITH_AES_256_CBC_SHA");
  (0x0036, "DH_DSS_WITH_AES_256_CBC_SHA");
  (0x0037, "DH_RSA_WITH_AES_256_CBC_SHA");
  (0x0038, "DHE_DSS_WITH_AES_256_CBC_SHA");
  (0x0039, "DHE_RSA_WITH_AES_256_CBC_SHA");
  (0x003a, "DH_anon_WITH_AES_256_CBC_SHA");
  (0x003b, "RSA_WITH_NULL_SHA256");
  (0x003c, "RSA_WITH_AES_128_CBC_SHA256");
  (0x003d, "RSA_WITH_AES_256_CBC_SHA256");
  (0x003e, "DH_DSS_WITH_AES_128_CBC_SHA256");
  (0x003f, "DH_RSA_WITH_AES_128_CBC_SHA256");
  (0x0040, "DHE_DSS_WITH_AES_128_CBC_SHA256");
  (0x0041, "RSA_WITH_CAMELLIA_128_CBC_SHA");
  (0x0042, "DH_DSS_WITH_CAMELLIA_128_CBC_SHA");
  (0x0043, "DH_RSA_WITH_CAMELLIA_128_CBC_SHA");
  (0x0044, "DHE_DSS_WITH_CAMELLIA_128_CBC_SHA");
  (0x0045, "DHE_RSA_WITH_CAMELLIA_128_CBC_SHA");
  (0x0046, "DH_anon_WITH_CAMELLIA_128_CBC_SHA");
  (0x0067, "DHE_RSA_WITH_AES_128_CBC_SHA256");
  (0x0068, "DH_DSS_WITH_AES_256_CBC_SHA256");
  (0x0069, "DH_RSA_WITH_AES_256_CBC_SHA256");
  (0x006a, "DHE_DSS_WITH_AES_256_CBC_SHA256");
  (0x006b, "DHE_RSA_WITH_AES_256_CBC_SHA256");
  (0x006c, "DH_anon_WITH_AES_128_CBC_SHA256");
  (0x006d, "DH_anon_WITH_AES_256_CBC_SHA256");
  (0x0084, "RSA_WITH_CAMELLIA_256_CBC_SHA");
  (0x0085, "DH_DSS_WITH_CAMELLIA_256_CBC_SHA");
  (0x0086, "DH_RSA_WITH_CAMELLIA_256_CBC_SHA");
  (0x0087, "DHE_DSS_WITH_CAMELLIA_256_CBC_SHA");
  (0x0088, "DHE_RSA_WITH_CAMELLIA_256_CBC_SHA");
  (0x0089, "DH_anon_WITH_CAMELLIA_256_CBC_SHA");
  (0x008a, "PSK_WITH_RC4_128_SHA");
  (0x008b, "PSK_WITH_3DES_EDE_CBC_SHA");
  (0x008c, "PSK_WITH_AES_128_CBC_SHA");
  (0x008d, "PSK_WITH_AES_256_CBC_SHA");
  (0x008e, "DHE_PSK_WITH_RC4_128_SHA");
  (0x008f, "DHE_PSK_WITH_3DES_EDE_CBC_SHA");
  (0x0090, "DHE_PSK_WITH_AES_128_CBC_SHA");
  (0x0091, "DHE_PSK_WITH_AES_256_CBC_SHA");
  (0x0092, "RSA_PSK_WITH_RC4_128_SHA");
  (0x0093, "RSA_PSK_WITH_3DES_EDE_CBC_SHA");
  (0x0094, "RSA_PSK_WITH_AES_128_CBC_SHA");
  (0x0095, "RSA_PSK_WITH_AES_256_CBC_SHA");
  (0x0096, "RSA_WITH_SEED_CBC_SHA");
  (0x0097, "DH_DSS_WITH_SEED_CBC_SHA");
  (0x0098, "DH_RSA_WITH_SEED_CBC_SHA");
  (0x0099, "DHE_DSS_WITH_SEED_CBC_SHA");
  (0x009a, "DHE_RSA_WITH_SEED_CBC_SHA");
  (0x009b, "DH_anon_WITH_SEED_CBC_SHA");
  (0x009c, "RSA_WITH_AES_128_GCM_SHA256");
  (0x009d, "RSA_WITH_AES_256_GCM_SHA384");
  (0x009e, "DHE_RSA_WITH_AES_128_GCM_SHA256");
  (0x009f, "DHE_RSA_WITH_AES_256_GCM_SHA384");
  (0x00a0, "DH_RSA_WITH_AES_128_GCM_SHA256");
  (0x00a1, "DH_RSA_WITH_AES_256_GCM_SHA384");
  (0x00a2, "DHE_DSS_WITH_AES_128_GCM_SHA256");
  (0x00a3, "DHE_DSS_WITH_AES_256_GCM_SHA384");
  (0x00a4, "DH_DSS_WITH_AES_128_GCM_SHA256");
  (0x00a5, "DH_DSS_WITH_AES_256_GCM_SHA384");
  (0x00a6, "DH_anon_WITH_AES_128_GCM_SHA256");
  (0x00a7, "DH_anon_WITH_AES_256_GCM_SHA384");
  (0x00a8, "PSK_WITH_AES_128_GCM_SHA256");
  (0x00a9, "PSK_WITH_AES_256_GCM_SHA384");
  (0x00aa, "DHE_PSK_WITH_AES_128_GCM_SHA256");
  (0x00ab, "DHE_PSK_WITH_AES_256_GCM_SHA384");
  (0x00ac, "RSA_PSK_WITH_AES_128_GCM_SHA256");
  (0x00ad, "RSA_PSK_WITH_AES_256_GCM_SHA384");
  (0x00ae, "PSK_WITH_AES_128_CBC_SHA256");
  (0x00af, "PSK_WITH_AES_256_CBC_SHA384");
  (0x00b0, "PSK_WITH_NULL_SHA256");
  (0x00b1, "PSK_WITH_NULL_SHA384");
  (0x00b2, "DHE_PSK_WITH_AES_128_CBC_SHA256");
  (0x00b3, "DHE_PSK_WITH_AES_256_CBC_SHA384");
  (0x00b4, "DHE_PSK_WITH_NULL_SHA256");
  (0x00b5, "DHE_PSK_WITH_NULL_SHA384");
  (0x00b6, "RSA_PSK_WITH_AES_128_CBC_SHA256");
  (0x00b7, "RSA_PSK_WITH_AES_256_CBC_SHA384");
  (0x00b8, "RSA_PSK_WITH_NULL_SHA256");
  (0x00b9, "RSA_PSK_WITH_NULL_SHA384");
  (0x00ba, "RSA_WITH_CAMELLIA_128_CBC_SHA256");
  (0x00bb, "DH_DSS_WITH_CAMELLIA_128_CBC_SHA256");
  (0x00bc, "DH_RSA_WITH_CAMELLIA_128_CBC_SHA256");
  (0x00bd, "DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256");
  (0x00be, "DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256");
  (0x00bf, "DH_anon_WITH_CAMELLIA_128_CBC_SHA256");
  (0x00c0, "RSA_WITH_CAMELLIA_256_CBC_SHA256");
  (0x00c1, "DH_DSS_WITH_CAMELLIA_256_CBC_SHA256");
  (0x00c2, "DH_RSA_WITH_CAMELLIA_256_CBC_SHA256");
  (0x00c3, "DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256");
  (0x00c4, "DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256");
  (0x00c5, "DH_anon_WITH_CAMELLIA_256_CBC_SHA256");
  (0x00ff, "EMPTY_RENEGOTIATION_INFO_SCSV");
  (0xc001, "ECDH_ECDSA_WITH_NULL_SHA");
  (0xc002, "ECDH_ECDSA_WITH_RC4_128_SHA");
  (0xc003, "ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA");
  (0xc004, "ECDH_ECDSA_WITH_AES_128_CBC_SHA");
  (0xc005, "ECDH_ECDSA_WITH_AES_256_CBC_SHA");
  (0xc006, "ECDHE_ECDSA_WITH_NULL_SHA");
  (0xc007, "ECDHE_ECDSA_WITH_RC4_128_SHA");
  (0xc008, "ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA");
  (0xc009, "ECDHE_ECDSA_WITH_AES_128_CBC_SHA");
  (0xc00a, "ECDHE_ECDSA_WITH_AES_256_CBC_SHA");
  (0xc00b, "ECDH_RSA_WITH_NULL_SHA");
  (0xc00c, "ECDH_RSA_WITH_RC4_128_SHA");
  (0xc00d, "ECDH_RSA_WITH_3DES_EDE_CBC_SHA");
  (0xc00e, "ECDH_RSA_WITH_AES_128_CBC_SHA");
  (0xc00f, "ECDH_RSA_WITH_AES_256_CBC_SHA");
  (0xc010, "ECDHE_RSA_WITH_NULL_SHA");
  (0xc011, "ECDHE_RSA_WITH_RC4_128_SHA");
  (0xc012, "ECDHE_RSA_WITH_3DES_EDE_CBC_SHA");
  (0xc013, "ECDHE_RSA_WITH_AES_128_CBC_SHA");
  (0xc014, "ECDHE_RSA_WITH_AES_256_CBC_SHA");
  (0xc015, "ECDH_anon_WITH_NULL_SHA");
  (0xc016, "ECDH_anon_WITH_RC4_128_SHA");
  (0xc017, "ECDH_anon_WITH_3DES_EDE_CBC_SHA");
  (0xc018, "ECDH_anon_WITH_AES_128_CBC_SHA");
  (0xc019, "ECDH_anon_WITH_AES_256_CBC_SHA");
  (0xc01a, "SRP_SHA_WITH_3DES_EDE_CBC_SHA");
  (0xc01b, "SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA");
  (0xc01c, "SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA");
  (0xc01d, "SRP_SHA_WITH_AES_128_CBC_SHA");
  (0xc01e, "SRP_SHA_RSA_WITH_AES_128_CBC_SHA");
  (0xc01f, "SRP_SHA_DSS_WITH_AES_128_CBC_SHA");
  (0xc020, "SRP_SHA_WITH_AES_256_CBC_SHA");
  (0xc021, "SRP_SHA_RSA_WITH_AES_256_CBC_SHA");
  (0xc022, "SRP_SHA_DSS_WITH_AES_256_CBC_SHA");
  (0xc023, "ECDHE_ECDSA_WITH_AES_128_CBC_SHA256");
  (0xc024, "ECDHE_ECDSA_WITH_AES_256_CBC_SHA384");
  (0xc025, "ECDH_ECDSA_WITH_AES_128_CBC_SHA256");
  (0xc026, "ECDH_ECDSA_WITH_AES_256_CBC_SHA384");
  (0xc027, "ECDHE_RSA_WITH_AES_128_CBC_SHA256");
  (0xc028, "ECDHE_RSA_WITH_AES_256_CBC_SHA384");
  (0xc029, "ECDH_RSA_WITH_AES_128_CBC_SHA256");
  (0xc02a, "ECDH_RSA_WITH_AES_256_CBC_SHA384");
  (0xc02b, "ECDHE_ECDSA_WITH_AES_128_GCM_SHA256");
  (0xc02c, "ECDHE_ECDSA_WITH_AES_256_GCM_SHA384");
  (0xc02d, "ECDH_ECDSA_WITH_AES_128_GCM_SHA256");
  (0xc02e, "ECDH_ECDSA_WITH_AES_256_GCM_SHA384");
  (0xc02f, "ECDHE_RSA_WITH_AES_128_GCM_SHA256");
  (0xc030, "ECDHE_RSA_WITH_AES_256_GCM_SHA384");
  (0xc031, "ECDH_RSA_WITH_AES_128_GCM_SHA256");
  (0xc032, "ECDH_RSA_WITH_AES_256_GCM_SHA384");
  (0xc033, "ECDHE_PSK_WITH_RC4_128_SHA");
  (0xc034, "ECDHE_PSK_WITH_3DES_EDE_CBC_SHA");
  (0xc035, "ECDHE_PSK_WITH_AES_128_CBC_SHA");
  (0xc036, "ECDHE_PSK_WITH_AES_256_CBC_SHA");
  (0xc037, "ECDHE_PSK_WITH_AES_128_CBC_SHA256");
  (0xc038, "ECDHE_PSK_WITH_AES_256_CBC_SHA384");
  (0xc039, "ECDHE_PSK_WITH_NULL_SHA");
  (0xc03a, "ECDHE_PSK_WITH_NULL_SHA256");
  (0xc03b, "ECDHE_PSK_WITH_NULL_SHA384");
  (0xc03c, "RSA_WITH_ARIA_128_CBC_SHA256");
  (0xc03d, "RSA_WITH_ARIA_256_CBC_SHA384");
  (0xc03e, "DH_DSS_WITH_ARIA_128_CBC_SHA256");
  (0xc03f, "DH_DSS_WITH_ARIA_256_CBC_SHA384");
  (0xc040, "DH_RSA_WITH_ARIA_128_CBC_SHA256");
  (0xc041, "DH_RSA_WITH_ARIA_256_CBC_SHA384");
  (0xc042, "DHE_DSS_WITH_ARIA_128_CBC_SHA256");
  (0xc043, "DHE_DSS_WITH_ARIA_256_CBC_SHA384");
  (0xc044, "DHE_RSA_WITH_ARIA_128_CBC_SHA256");
  (0xc045, "DHE_RSA_WITH_ARIA_256_CBC_SHA384");
  (0xc046, "DH_anon_WITH_ARIA_128_CBC_SHA256");
  (0xc047, "DH_anon_WITH_ARIA_256_CBC_SHA384");
  (0xc048, "ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256");
  (0xc049, "ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384");
  (0xc04a, "ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256");
  (0xc04b, "ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384");
  (0xc04c, "ECDHE_RSA_WITH_ARIA_128_CBC_SHA256");
  (0xc04d, "ECDHE_RSA_WITH_ARIA_256_CBC_SHA384");
  (0xc04e, "ECDH_RSA_WITH_ARIA_128_CBC_SHA256");
  (0xc04f, "ECDH_RSA_WITH_ARIA_256_CBC_SHA384");
  (0xc050, "RSA_WITH_ARIA_128_GCM_SHA256");
  (0xc051, "RSA_WITH_ARIA_256_GCM_SHA384");
  (0xc052, "DHE_RSA_WITH_ARIA_128_GCM_SHA256");
  (0xc053, "DHE_RSA_WITH_ARIA_256_GCM_SHA384");
  (0xc054, "DH_RSA_WITH_ARIA_128_GCM_SHA256");
  (0xc055, "DH_RSA_WITH_ARIA_256_GCM_SHA384");
  (0xc056, "DHE_DSS_WITH_ARIA_128_GCM_SHA256");
  (0xc057, "DHE_DSS_WITH_ARIA_256_GCM_SHA384");
  (0xc058, "DH_DSS_WITH_ARIA_128_GCM_SHA256");
  (0xc059, "DH_DSS_WITH_ARIA_256_GCM_SHA384");
  (0xc05a, "DH_anon_WITH_ARIA_128_GCM_SHA256");
  (0xc05b, "DH_anon_WITH_ARIA_256_GCM_SHA384");
  (0xc05c, "ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256");
  (0xc05d, "ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384");
  (0xc05e, "ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256");
  (0xc05f, "ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384");
  (0xc060, "ECDHE_RSA_WITH_ARIA_128_GCM_SHA256");
  (0xc061, "ECDHE_RSA_WITH_ARIA_256_GCM_SHA384");
  (0xc062, "ECDH_RSA_WITH_ARIA_128_GCM_SHA256");
  (0xc063, "ECDH_RSA_WITH_ARIA_256_GCM_SHA384");
  (0xc064, "PSK_WITH_ARIA_128_CBC_SHA256");
  (0xc065, "PSK_WITH_ARIA_256_CBC_SHA384");
  (0xc066, "DHE_PSK_WITH_ARIA_128_CBC_SHA256");
  (0xc067, "DHE_PSK_WITH_ARIA_256_CBC_SHA384");
  (0xc068, "RSA_PSK_WITH_ARIA_128_CBC_SHA256");
  (0xc069, "RSA_PSK_WITH_ARIA_256_CBC_SHA384");
  (0xc06a, "PSK_WITH_ARIA_128_GCM_SHA256");
  (0xc06b, "PSK_WITH_ARIA_256_GCM_SHA384");
  (0xc06c, "DHE_PSK_WITH_ARIA_128_GCM_SHA256");
  (0xc06d, "DHE_PSK_WITH_ARIA_256_GCM_SHA384");
  (0xc06e, "RSA_PSK_WITH_ARIA_128_GCM_SHA256");
  (0xc06f, "RSA_PSK_WITH_ARIA_256_GCM_SHA384");
  (0xc070, "ECDHE_PSK_WITH_ARIA_128_CBC_SHA256");
  (0xc071, "ECDHE_PSK_WITH_ARIA_256_CBC_SHA384")
]

let cipher_suite_string_of_int, cipher_suite_int_of_string =
  let n = List.length cipher_suite_strings in
  let soi_hash = Hashtbl.create n in
  let ios_hash = Hashtbl.create n in
  let populate_hash (i, s) =
    Hashtbl.replace soi_hash i s;
    Hashtbl.replace ios_hash s i
  in
  List.iter populate_hash cipher_suite_strings;
  let cs_soi i =
    try Hashtbl.find soi_hash i
    with Not_found -> ("Unknown ciphersuite " ^ (string_of_int i))
  and cs_ios s =      
    try Hashtbl.find ios_hash s
    with Not_found -> int_of_string s
  in cs_soi, cs_ios

let parse_ciphersuite pstate =
  let v = pop_uint16 pstate in
  V_Enumerated (v, cipher_suite_string_of_int)

let _make_cipher_suite = function
  | V_Int i
  | V_Enumerated (i, _) -> i
  | V_String s -> cipher_suite_int_of_string s
  | _ -> raise (ContentError "Invalid cipher suite value")

let make_cipher_suite v = V_Enumerated (_make_cipher_suite v, cipher_suite_string_of_int)


(* Compression method *)

type compression_method = int

let compression_method_strings = [
  (0x00, "NULL");
  (0x01, "DEFLATE");
  (0x40, "LZS")
]

let compression_method_string_of_int, compression_method_int_of_string =
  let n = List.length compression_method_strings in
  let soi_hash = Hashtbl.create n in
  let ios_hash = Hashtbl.create n in
  let populate_hash (i, s) =
    Hashtbl.replace soi_hash i s;
    Hashtbl.replace ios_hash s i
  in
  List.iter populate_hash compression_method_strings;
  let cm_soi i =
    try Hashtbl.find soi_hash i
    with Not_found -> ("Unknown ciphersuite " ^ (string_of_int i))
  and cm_ios s =      
    try Hashtbl.find ios_hash s
    with Not_found -> int_of_string s
  in cm_soi, cm_ios

let parse_ciphersuite pstate =
  let v = pop_uint16 pstate in
  V_Enumerated (v, compression_method_string_of_int)

let _make_compression_method = function
  | V_Int i
  | V_Enumerated (i, _) -> i
  | V_String s -> compression_method_int_of_string s
  | _ -> raise (ContentError "Invalid cipher suite value")

let make_compression_method v = V_Enumerated (_make_compression_method v, compression_method_string_of_int)
