open Parsifal
open BasePTypes
open PTypes

struct counted_octet_string_blo = 
{
  size : uint16;
  content : string(size)
}

enum etype_type (16, UnknownVal UnknownEncryptType) =
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

enum name_type (32, UnknownVal UnknownNameType) = 
  | 1 -> KRB5_NT_PRINCIPAL, "KRB5_NT_PRINCIPAL"
  | 2 -> KRB5_NT_SRV_INST, "KRB5_SRV_INST"
  | 5 -> KRB5_NT_UID, "KRB5_NT_UID"

alias counted_octet_string = string[uint16]
struct keyblock = {
  etype : etype_type;
  key : binstring[uint16]
}

struct keytab_entry =
{
      num_components: uint16;    (* sub 1 if version 0x501 *)
      realm : counted_octet_string (* counted_octet_string *);
      components : list(num_components) of counted_octet_string;
      optional name_type: name_type;   (* not present if version 0x501 *)
      timestamp: uint32;
      vno8 : uint8;
      key : keyblock (* keyblock *);
      optional vno : uint32; (* only present if >= 4 bytes left in entry *)
} 

struct keytab_file =
{
  file_format_version : uint16;
  entries : list of container[uint32] of keytab_entry;
}

let rec handle_entry input =
  let entry = parse_keytab_file input in
  print_endline (print_value (value_of_keytab_file entry));
  handle_entry input

let _ =
  let input = string_input_of_filename "test.keytab" in
  handle_entry input
