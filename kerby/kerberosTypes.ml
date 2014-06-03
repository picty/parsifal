open Parsifal
open PTypes
open Asn1PTypes
open Asn1Engine
open X509Basics
open KerbyContainers

(* ContextSpecific optimization *)
type 'a cspe = 'a
let parse_cspe n parse_fun input = parse_asn1 (C_ContextSpecific, true, T_Unknown n) parse_fun input
let dump_cspe n dump_fun buf o = dump_asn1 (C_ContextSpecific, true, T_Unknown n) dump_fun buf o
let value_of_cspe = BasePTypes.value_of_container

(* DEFINITIONS *)
(* Define KerberosString *)
asn1_alias der_kerberos_string = primitive[T_GeneralString] der_printable_octetstring_content(no_constraint)
(* Define Sequence of KerberosString *)
asn1_alias seqkerbstring = seq_of der_kerberos_string
(* Define KerberosTime *)
alias der_kerberos_time = der_time

enum principalname_type (8, UnknownVal UnknownPrincipalNameType) =
  | 1 -> Principal
  | 2 -> Service_and_Instance
  | 3 -> Service_and_Host

let kdc_options_values = [|
  "RESERVED";
  "FORWARDABLE";
  "FORWARDED";
  "PROXIABLE";
  "PROXY";
  "ALLOW_POSTDATE";
  "POSTDATED";
  "RESERVED";
  "RENEWABLE";
  "RESERVED";
  "RESERVED";
  "RESERVED_OPT_HW_AUTH";
  "RESERVED";
  "RESERVED";
  "RESERVED_CONSTRAINED_DELEGATION";
  "RESERVED_CANONICALIZE";
  "RESERVED";
  "RESERVED";
  "RESERVED";
  "RESERVED";
  "RESERVED";
  "RESERVED";
  "RESERVED";
  "RESERVED";
  "RESERVED";
  "RESERVED";
  "DISABLE_TRANSITED_CHECK";
  "RENEWABLE_OK";
  "ENC_TKT_IN_SKEY";
  "RESERVED";
  "RENEW";
  "VALIDATE"
|]

let ap_options_values = [|
  "RESERVED";
  "USE_SESSION_KEY";
  "MUTUAL_REQUIRED";
  "RESERVED";
  "RESERVED";
  "RESERVED";
  "RESERVED";
  "RESERVED";
  "RESERVED";
  "RESERVED";
  "RESERVED";
  "RESERVED";
  "RESERVED";
  "RESERVED";
  "RESERVED";
  "RESERVED";
  "RESERVED";
  "RESERVED";
  "RESERVED";
  "RESERVED";
  "RESERVED";
  "RESERVED";
  "RESERVED";
  "RESERVED";
  "RESERVED";
  "RESERVED";
  "RESERVED";
  "RESERVED";
  "RESERVED";
  "RESERVED";
  "RESERVED";
  "RESERVED"
|]

struct cname_content =
{
  (*name_type : cspe [0] of der_smallint;*)
  name_type :   cspe [0] of asn1 [(C_Universal, false, T_Integer)] of principalname_type;
  name_string : cspe [1] of seqkerbstring
}
asn1_alias cname
alias sname = cname

enum addr_type (8, UnknownVal UnknownAddrType) =
  | 2 -> DIRECTIONNAL
  | 3 -> CHAOSNET
  | 5 -> XNS
  | 7 -> ISO
  | 12 -> DECNET_PHASE_IV
  | 16 -> APPLETALK_DDP
  | 20 -> NETBIOS
  | 24 -> IPV6

asn1_struct host_address =
{
  addr_type : cspe [0] of asn1 [(C_Universal, false, T_Integer)] of addr_type;
  address : cspe [1] of der_octetstring
}

asn1_alias host_addresses = seq_of host_address

enum pvno (8, UnknownVal UnknownProtocolVersion) =
  | 5 -> KerberosV5

enum msg_type (8, UnknownVal UnknownMsgType) =
  | 10 -> AS_REQ
  | 11 -> AS_REP
  | 12 -> TGS_REQ
  | 13 -> TGS_REP
  | 14 -> AP_REQ
  | 30 -> KRB_ERROR

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

struct encrypted_data_content [param usage; param key] =
{
  edc_encryption_type :     cspe [0] of asn1 [(C_Universal, false, T_Integer)] of etype_type;
  optional edc_kvno :       cspe [1] of der_smallint;
  edc_cipher :              cspe [2] of octetstring_container of aes_container (usage; edc_kvno; key) of binstring;
}
asn1_alias encrypted_data [param usage; param key] = sequence encrypted_data_content(usage; key)

type 'a encrypted_data_container = {
  encryption_type : etype_type;
  kvno : int option;
  cipher : 'a crypto_container;
}

let parse_encrypted_data_container usage key name parse_fun input =
  let enc_data = parse_encrypted_data usage key input in
  let cipher = match enc_data.edc_cipher with
    | ( DecryptionError | Encrypted _ ) as res -> res
    | Decrypted s ->
      try
        let new_input = get_in_container input name s in
        let res = parse_fun new_input in
        check_empty_input true new_input;
        Decrypted res
      with _ -> DecryptionError
  in {
    encryption_type = enc_data.edc_encryption_type;
    kvno = enc_data.edc_kvno;
    cipher = cipher;
  }

let dump_encrypted_data_container _dump_fun _buf _o = not_implemented "dump_encrypted_data_container"

let value_of_encrypted_data_container value_of_fun v = VRecord [
  "@name", VString ("encrypted_data_container", false);
  "encryption_type", value_of_etype_type v.encryption_type;
  "kvno", (match v.kvno with None -> VUnit | Some i -> VSimpleInt i);
  "cipher", value_of_crypto_container value_of_fun v.cipher
  ]

struct ticket_content [param key] =
{
  tkvno : cspe [0] of der_smallint;
  realm : cspe [1] of der_kerberos_string;
  sname : cspe [2] of sname;
  enc_tkt_part : cspe [3] of encrypted_data_container (2; key) of der_object;
}
asn1_alias ticket [param key] = sequence ticket_content(key)
