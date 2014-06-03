open Parsifal
open BasePTypes
open PTypes
open Asn1PTypes
open Asn1Engine
open X509Basics
open KerbyContainers

let global_session_key = ref None
let parse_init_session_key key _ = global_session_key := Some key

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
(*alias der_kerberos_time = der_time*)
(* Should be a der_time, but some implementation seems not to include the final "Z" char *)
asn1_alias der_kerberos_time = primitive[T_GeneralizedTime] der_printable_octetstring_content(no_constraint)

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

let ticket_options_values = [|
  "RESERVED0";
  "FORWARDABLE";
  "FORWARDED";
  "PROXIABLE";
  "PROXY";
  "MAY_POSTDATE";
  "POSTDATED";
  "INVALID";
  "RENEWABLE";
  "INITIAL";
  "PRE-AUTHENT";
  "RESERVED_OPT_HW_AUTH";
  "TRANSITED_POLICY_CHECKED";
  "OK_AS_DELEGATE";
  "RESERVED14";
  "RESERVED15";
  "RESERVED16";
  "RESERVED17";
  "RESERVED18";
  "RESERVED19";
  "RESERVED20";
  "RESERVED21";
  "RESERVED22";
  "RESERVED23";
  "RESERVED24";
  "RESERVED25";
  "RESERVED26";
  "RESERVED27";
  "RESERVED28";
  "RESERVED29";
  "RESERVED30";
  "RESERVED31"
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

asn1_struct encryption_key =
{
  key_type :     cspe [0] of asn1 [(C_Universal, false, T_Integer)] of etype_type;
  key_value :    cspe [1] of der_octetstring;
  parse_checkpoint : init_session_key(key_value)
}

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

asn1_struct ad_subentry = {
  ads_type : cspe [0] of der_smallint;
  ads_content : cspe [1] of octetstring_container of binstring;
}


asn1_struct authorization_data_entry = {
  ade_type : cspe [0] of der_integer;
  (* Warning: ade_content may depend on ade_type. For the moment, we suppose ade_type = 1 *)
  ade_content : cspe [1] of octetstring_container of asn1 [(C_Universal, true, T_Sequence)] of list of ad_subentry;
}

asn1_alias authorization_data = seq_of authorization_data_entry

asn1_struct transited_encoding = {
  tr_type : cspe [0] of der_integer;
  contents : cspe [1] of octetstring_container of binstring;
}

asn1_struct enc_ticket_part =
{
  flags : cspe [0] of der_enumerated_bitstring[ticket_options_values];
  key : cspe [1] of encryption_key;
  crealm : cspe [2] of der_kerberos_string;
  cname : cspe [3] of cname;
  transited : cspe [4] of transited_encoding;
  authtime : cspe [5] of der_kerberos_time;
  optional starttime : cspe [6] of der_kerberos_time;
  endtime : cspe [7] of der_kerberos_time;
  optional renew_till : cspe [8] of der_kerberos_time;
  optional caddr : cspe [9] of binstring;
  optional authorization_data : cspe [10] of authorization_data;
}

struct ticket_content [param key] =
{
  tkvno : cspe [0] of der_smallint;
  realm : cspe [1] of der_kerberos_string;
  sname : cspe [2] of sname;
  enc_tkt_part : cspe [3] of encrypted_data_container (2; key) of asn1 [(C_Application, true, T_Unknown 3)] of enc_ticket_part;
}
asn1_alias ticket [param key] = sequence ticket_content(key)

asn1_alias tickets = seq_of asn1 [(C_Application, true, T_Unknown 1)] of ticket(None)

(* FIXME, use it to parse gss_checksum.flags *)
(*
let ctx_establishment_options_values = [|
  "GSS_C_DELEG_FLAG";
  "GSS_C_MUTUAL_FLAG";
  "GSS_C_REPLAY_FLAG";
  "GSS_C_SEQUENCE_FLAG";
  "GSS_C_CONF_FLAG";
  "GSS_C_INTEG_FLAG";
|]
*)

struct krb_cred_content = {
  pvno : cspe[0] of der_smallint;
  msg_type : cspe[1] of der_smallint;
  tickets : cspe[2] of tickets;
  enc_part : cspe[3] of encrypted_data_container (0; None) of binstring;
}
asn1_alias krb_cred = seq_of krb_cred_content

struct gss_checksum = {
  lgth : uint32le;
  bnd : binstring(16); (* can be a md5 hash *)
  flags : uint32le; (* should parse bitfield accoring to ctx_establishment_options_values *)
  dlg_opt : uint16le; (* when present should be equal to 1 *)
  dlg_length : uint16le; (* length of following deleg field (krb_cred structure) *)
  deleg : asn1 [(C_Application, true, T_Unknown 22)] of krb_cred;
}

union cksum_value [enrich] (UnparsedChecksumValueContent) =
  | 1  -> CRC32 of binstring
  | 2  -> RSA_MD4 of binstring
  | 3  -> RSA_MD4_DES of binstring
  | 4  -> DES_MAC of binstring
  | 5  -> DES_MAC_K of binstring
  | 6  -> RSA_MD4_DES_K of binstring
  | 7  -> RSA_MD5 of binstring
  | 8  -> RSA_MD5_DES of binstring
  | 9  -> RSA_MD5_DES3 of binstring
  | 10  -> SHA1_UNKEYED of binstring
  | 12  -> HMAC_SHA1_DES3_KD of binstring
  | 13  -> HMAC_SHA1_DES3 of binstring
  | 14  -> SHA1_UNKEYED_OTHER of binstring
  | 15 -> HMAC_SHA1_96_AES128 of binstring
  | 16 -> HMAC_SHA1_96_AES256 of binstring
  | 32771 -> GSS_CHECKSUM of gss_checksum

asn1_struct checksum =
{
  cksum_type :     cspe [0] of asn1 [(C_Universal, false, T_Integer)] of der_smallint_content;
  cksum_value :    cspe [1] of octetstring_container of cksum_value(cksum_type)
}
