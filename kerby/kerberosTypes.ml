open Parsifal
open PTypes
open Asn1PTypes
open Asn1Engine

(* ContextSpecific optimization *)
type 'a cspe = 'a
let parse_cspe n parse_fun input = parse_asn1 (C_ContextSpecific, true, T_Unknown n) parse_fun input
let dump_cspe n dump_fun buf o = dump_asn1 (C_ContextSpecific, true, T_Unknown n) dump_fun buf o
let value_of_cspe = BasePTypes.value_of_container

enum etype_type (8, UnknownVal UnknownEncryptType) =
  | 1  -> DES_CBC_CRC
  | 2  -> DES_CBC_MD4
  | 3  -> DES_CBC_MD5
  | 5  -> DES3_CBC_MD5
  | 16 -> DES3_CBC_SHA1
  | 17 -> AES128_CTS_HMAC_SHA1_96
  | 18 -> AES256_CTS_HMAC_SHA1_96
  | 23 -> RC4_HMAC
  | 24 -> RC4_HMAC_EXP
  | 25 -> CAMELLIA128_CTS_CMAC
  | 26 -> CAMELLIA256_CTS_CMAC
(* FIXME CANNOT USE ETYPE correctly because der_smallint overflows*)
(*
  | -128 -> RC4_MD4
  | -133 -> RC4_HMAC_OLD
  | -135 -> RC4_HMAC_OLD_EXP
*)

asn1_struct encrypted_data =
{
  encryption_type :     cspe [0] of asn1 [(C_Universal, false, T_Integer)] of etype_type;
  optional kvno :       cspe [1] of der_smallint;
  cipher :              cspe [2] of der_octetstring
}
