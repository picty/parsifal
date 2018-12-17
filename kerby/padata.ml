open Asn1PTypes
open Asn1Engine
open X509
open X509Basics
open X509Extensions
open Pkcs7
open KerberosTypes

open Pkcs1
open CryptoUtil
open KerbyContainers


let rsa_key = ref NoRSAKey

let global_des3_key = ref None
let parse_init_des3_key des3_key _ = match des3_key with
  | RSADecrypted k -> global_des3_key := Some k
  | RSAEncrypted _ -> global_des3_key := None

let aes_ticket_key = ref None


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

let pa_pac_options_values = [|
  "CLAIMS";
  "BRANCH_AWARE";
  "FORWARD_TO_FULL_DC";
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

asn1_struct pk_authenticator =
{
  cusec : cspe [0] of der_smallint;
  ctime : cspe [1] of der_kerberos_time;
  nonce : cspe [2] of der_smallint; (* Chosen randomly, does not need to match KDC-REQ-BODY one *)
  optional pa_checksum : cspe[3] of der_octetstring (* SHA1 checksum or KDC-REQ-BODY *)
}

asn1_struct myoid =
{
  oid : cspe [0] of der_oid
}

asn1_alias oid_list = seq_of myoid

asn1_struct auth_pack = {
  pk_authenticator : cspe [0] of pk_authenticator;
  optional clientPublicValue : cspe [1] of subjectPublicKeyInfo;
  optional supported_cms_types : cspe [2] of sMIMECapabilities;
  (* FIXME Decode the two structures *)
  optional client_dh_nonce : cspe[3] of binstring;
  optional supported_KDFs : cspe[4] of oid_list
}

asn1_struct kdc_dh_key_info = {
  subject_public_key : cspe [0] of der_bitstring;
  nonce : cspe [1] of der_smallint;
  optional dh_key_expiration : cspe [2] of der_kerberos_time
}

asn1_struct reply_key_pack = {
  reply_key : cspe [0] of encryption_key;
  as_checksum : cspe [1] of der_object;
  parse_checkpoint : KerberosTypes.init_session_key(reply_key.key_value)
}

union krbContentInfo_value [enrich] (UnparsedKrbContentInfo of binstring) =
 | [43;6;1;5;2;3;1] -> ID_PKINIT_AuthData of auth_pack
 | [43;6;1;5;2;3;2] -> ID_PKINIT_DHKeyData of kdc_dh_key_info
 | [43;6;1;5;2;3;3] -> ID_PKINIT_RKeyData of reply_key_pack

asn1_struct krbContentInfo = {
  oid : der_oid;
  contentInfo : asn1 [(C_ContextSpecific, true, T_Unknown 0)] of octetstring_container of krbContentInfo_value(oid)
}

struct mysignerInfo_content = {
  version : der_smallint;
  (* FIXME Ugly hack, because Heimdal does not seem to use normal issuerAndSerial structure *)
  (* issuerAndSerialNumber : issuerAndSerialNumber; *)
  issuerAndSerialNumber_FIXME : der_object;
  digestAlgorithm : algorithmIdentifier;
  optional authenticatedAttributesUNPARSED : authenticatedAttributes;
  digestEncryptionAlgorithm : algorithmIdentifier;
  encryptedDigest : der_octetstring;
  optional unAuthenticatedAttributesUNPARSED : unauthenticatedAttributes
}
asn1_alias mysignerInfo

asn1_struct kerb_pkcs7_signed_data = {
  version : der_smallint;
  digestAlgorithms : digestAlgorithmIdentifiers;
  contentInfo : krbContentInfo;
  optional certificates : cspe [0] of (list of certificate);
  optional crls : cspe [0] of (list of binstring);
  (* FIXME Ugly hack, because Heimdal does not seem to use normal issuerAndSerial structure *)
  signerInfos : asn1 [(C_Universal, true, T_Set)] of (list of mysignerInfo);
}

(* Only 2 possible values *)
union recipientIdentifier_value [enrich] (UnparsedRecipientIdentifier)=
 | 0 -> IssuerAndSerialNumber of issuerAndSerialNumber
 | 2 -> SubjectKeyIdentifier of cspe [0] of der_octetstring

(* FIXME encryptedKey is the 3DES wrapped key with RSA *)
struct keyTransRecipientInfo =
{
  version : der_smallint;
  rid : recipientIdentifier_value(version);
  keyEncryptionAlgorithm : algorithmIdentifier;
  encryptedKey : octetstring_container of pkcs1_container (!rsa_key) of binstring;
  parse_checkpoint : init_des3_key(encryptedKey)
}

(* FIXME Implement proper definition *)
alias keyAgreeRecipientInfo = binstring
alias keKRecipientInfo = binstring
alias passwordRecipientInfo = binstring
alias otherRecipientInfo = binstring

asn1_struct recipientInfo =
{
  ktri : keyTransRecipientInfo;
  optional kari :  cspe [1] of keyAgreeRecipientInfo;
  optional kekri : cspe [2] of keKRecipientInfo;
  optional pwri :  cspe [3] of passwordRecipientInfo;
  optional ori :   cspe [4] of otherRecipientInfo;
}


(* FIXME encryptedContent is the encrypted replyKeyPack with 3DES, IV is in
   in params of contentEncryptionAlgorithm, once decrypted, should be fed to
   a kerb_pkcs7 struct.
*)
asn1_struct encryptedContentInfo =
{
  contentType : der_oid;
  contentEncryptionAlgorithm : algorithmIdentifier;
  optional encryptedContent : asn1 [(C_ContextSpecific, false, T_Unknown 0)] of
      des3_container (contentEncryptionAlgorithm.algorithmParams; !global_des3_key) of kerb_pkcs7_signed_data
}

(* FIXME Implement originatorInfo/unprotectedAttrs *)
asn1_struct kerb_pkcs7_enveloped_data = {
  version : der_smallint;
  optional originatorInfo : cspe [0] of binstring;
  recipientInfo : asn1 [(C_Universal, true, T_Set)] of (list of recipientInfo);
  encryptedContentInfo : encryptedContentInfo;
  optional unprotectedAttrs : cspe [1] of (list of binstring);
}

union p7_content [enrich] (Unspecified of der_object) =
  | [42;840;113549;1;7;2] -> SignedData of kerb_pkcs7_signed_data
  | [42;840;113549;1;7;3] -> EnvelopedData of kerb_pkcs7_enveloped_data

asn1_struct kerb_pkcs7 = {
  p7_content_type : der_oid;
  p7_content : cspe [0] of p7_content(p7_content_type)
}

struct externalPrincipalIdentifier_content = {
 optional subjectName : asn1 [(C_ContextSpecific, false, T_Unknown 0)] of distinguishedName;
 optional issuerAndSerialNumber : asn1 [(C_ContextSpecific, false, T_Unknown 1)] of issuerAndSerialNumber;
 optional subjectKeyIdentifier : asn1 [(C_ContextSpecific, false, T_Unknown 2)] of der_octetstring;
}
asn1_alias externalPrincipalIdentifier
asn1_alias externalPrincipalIdentifiers = seq_of externalPrincipalIdentifier

asn1_struct pa_pk_as_req =
{
  (*
  signed_auth_pack_TOFIX : asn1 [(C_ContextSpecific, false, T_Unknown 0)] of binstring;
  *)
  (* TODO better test CMS (PKCS#7) *)
  signed_auth_pack : asn1 [(C_ContextSpecific, false, T_Unknown 0)] of kerb_pkcs7;
  optional trusted_certifiers : cspe [1] of externalPrincipalIdentifiers;
  optional kdc_pk_id : cspe [2] of binstring
}

asn1_struct dhrepinfo =
{
  dh_signed_data : asn1 [(C_ContextSpecific, false, T_Unknown 0)] of kerb_pkcs7;
  optional server_dh_nonce : cspe [1] of binstring;
  optional kdf_id : cspe [2] of myoid
}

struct pa_pk_as_rep =
{
  optional dhinfo : cspe [0] of dhrepinfo;
  optional encKeypack : asn1 [(C_ContextSpecific, false, T_Unknown 1)] of kerb_pkcs7;
  (*
  (* or (ASN.1 CHOICE ! *)
  enckeypack : asn1 [(C_ContextSpecific, false, T_Unknown 0)] of binstring
  pa_pk_as_rep_FIXME : binstring
  *)
}

asn1_struct etype_info =
{
  etype : cspe [0] of asn1 [(C_Universal, false, T_Integer)] of etype_type;
  optional salt : cspe [1] of der_kerberos_string;
}
asn1_alias etype_infos = seq_of etype_info

asn1_struct etype_info2 =
{
  etype : cspe [0] of asn1 [(C_Universal, false, T_Integer)] of etype_type;
  optional salt : cspe [1] of der_kerberos_string;
  optional s2kparams : cspe [2] of der_octetstring
}
asn1_alias etype_info2s = seq_of etype_info2

(* DEBUG pa_pk_as_rep *)
(*
let parse_pa_pk_as_rep input =
  let o = input.cur_offset in
  Printf.printf "%s\n" (hexdump (BasePTypes.parse_rem_string input));
  input.cur_offset <- o;
  parse_pa_pk_as_rep input
*)

asn1_struct pa_pac_options =
{
  pa_pac_options : cspe [0] of der_enumerated_bitstring[pa_pac_options_values];
}

asn1_struct authenticator = {
  authenticator_vno : cspe [0] of asn1 [(C_Universal, false, T_Integer)] of pvno;
  crealm : cspe [1] of der_kerberos_string;
  cname : cspe [2] of cname;
  optional cksum : cspe [3] of checksum;
  cusec : cspe [4] of der_smallint;
  ctime : cspe [5] of der_kerberos_time;
  optional subkey : cspe [6] of encryption_key;
  optional seq_number : cspe [7] of asn1 [(C_Universal, false, T_Integer)] of binstring;
  optional authorization_data : cspe [8] of authorization_data;
}

(* AP_REQ *)
(* The DER encoding of the following is
   encrypted in the ticket's session key, with a key usage value of 11
   in normal application exchanges, or 7 when used as the PA-TGS-REQ
   PA-DATA field of a TGS-REQ exchange (see Section 5.4.1) *)
struct ap_req_content [param krb5_keyusage] =
{
  pvno :        cspe [0] of asn1 [(C_Universal, false, T_Integer)] of pvno;
  msg_type :    cspe [1] of asn1 [(C_Universal, false, T_Integer)] of msg_type;
  ap_options :  cspe [2] of der_enumerated_bitstring[ap_options_values];
  ticket :      cspe [3] of asn1 [(C_Application, true, T_Unknown 1)] of ticket (!aes_ticket_key);
  authenticator : cspe [4] of encrypted_data_container (krb5_keyusage; !KerberosTypes.global_session_key) of asn1 [(C_Application, true, T_Unknown 2)] of authenticator;
}
asn1_alias ap_req [param krb5_keyusage] = sequence ap_req_content(krb5_keyusage)

union padata_value [enrich] (UnparsedPaDataValueContent of binstring) =
  | 1, true -> PA_TGS_REQ of asn1 [(C_Application, true, T_Unknown 14)] of ap_req(7)
  | 2, true -> PA_ENC_TIMESTAMP of encrypted_data (0; None)
  | 3, true -> PA_PW_SALT of binstring
  | 4, true -> RESERVED of binstring (* RFC6113 *)
  | 5, true -> PA_ENC_UNIX_TIME of binstring (* deprecated *)
  | 6, true -> PA_SANDIA_SECUREID of binstring
  | 7, true -> PA_SESAME of binstring
  | 8, true -> PA_OSF_DCE of binstring
  | 9, true -> PA_CYBERSAFE_SECUREID of binstring
  | 10, true ->  PA_AFS3_SALT of binstring (* [RFC4120] [RFC3961] *)
  | 11, _ -> PA_ENCTYPE_INFO of etype_infos
  | 12, true -> PA_SAM_CHALLENGE of binstring (* [KRB_WG.SAM] *)
  | 13, true -> PA_SAM_RESPONSE of binstring  (* [KRB_WG.SAM] *)
  | 14, true -> PA_PK_AS_REQ_OLD of binstring (* [PK_INIT_1999] *)
  | 15, true -> PA_PK_AS_REP_OLD of binstring (* [PK_INIT_1999] *)
  | 16, true -> PA_PK_AS_REQ of pa_pk_as_req  (* [RFC4556] FIXME Improve PKCS7 *)
  | 17, true -> PA_PK_AS_REP of pa_pk_as_rep  (* [RFC4556] FIXME Improve PKCS7 *)
  | 18, true -> PA_ENCTYPE_INFO_UNUSED of binstring
  | 19,  _ -> PA_ENCTYPE_INFO2 of etype_info2s
  | 20, true ->  PA_USE_SPECIFIED_KVNO_OR_PA_SVR_REFERRAL_INFO  of binstring (* [RFC4120] or [REFERRALS] *)
  | 21, true ->  PA_SAM_REDIRECT             of binstring (* [KRB_WG.SAM] *)
  | 22, true ->  PA_GET_FROM_TYPED_DATA_OR_TD_PADATA      of binstring (* (embedded in typed data) [RFC4120] or embeds padata) [RFC4120] *)
  | 23, true ->  PA_SAM_ETYPE_INFO           of binstring (* (sam/otp) [KRB_WG.SAM] *)
  | 24, true ->  PA_ALT_PRINC                of binstring (* (crawdad@fnal.gov) [HW_AUTH] *)
  | 25, true ->  PA_SERVER_REFERRAL          of binstring (* [REFERRALS] *)
  | 30, true ->  PA_SAM_CHALLENGE2           of binstring (* (kenh@pobox.com) [KRB_WG.SAM] *)
  | 31, true ->  PA_SAM_RESPONSE2            of binstring (* (kenh@pobox.com) [KRB_WG.SAM] *)
  | 41, true ->  PA_EXTRA_TGT                of binstring (* Reserved extra TGT [RFC6113] *)
  | 101, true ->  TD_PKINIT_CMS_CERTIFICATES of binstring (* CertificateSet from CMS *)
  | 102, true ->  TD_KRB_PRINCIPAL           of binstring (* PrincipalName *)
  | 103, true ->  TD_KRB_REALM               of binstring (* Realm *)
  | 104, true ->  TD_TRUSTED_CERTIFIERS      of binstring (* [RFC4556] *)
  | 105, true ->  TD_CERTIFICATE_INDEX       of binstring (* [RFC4556] *)
  | 106, true ->  TD_APP_DEFINED_ERROR       of binstring (* Application specific [RFC6113] *)
  | 107, true ->  TD_REQ_NONCE               of binstring (* INTEGER [RFC6113] *)
  | 108, true ->  TD_REQ_SEQ                 of binstring (* INTEGER [RFC6113] *)
  | 109, true ->  TD_DH_PARAMETERS           of binstring (* [RFC4556] *)
  | 111, true ->  TD_CMS_DIGEST_ALGORITHMS   of binstring (* [ALG_AGILITY] *)
  | 112, true ->  TD_CERT_DIGEST_ALGORITHMS  of binstring (* [ALG_AGILITY] *)
  | 128, true ->  PA_PAC_REQUEST             of binstring (* [MS_KILE] *)
  | 129, true ->  PA_FOR_USER                of binstring (* [MS_KILE] *)
  | 130, true ->  PA_FOR_X509_USER           of binstring (* [MS_KILE] *)
  | 131, true ->  PA_FOR_CHECK_DUPS          of binstring (* [MS_KILE] *)
  | 132, true ->  PA_AS_CHECKSUM             of binstring (* [MS_KILE] *)
  | 133, _ -> PA_FX_COOKIE of string (* RFC6113 *)
  | 134, true ->  PA_AUTHENTICATION_SET      of binstring (* [RFC6113] *)
  | 135, true ->  PA_AUTH_SET_SELECTED       of binstring (* [RFC6113] *)
  | 136, true ->  PA_FX_FAST                 of binstring (* [RFC6113] *)
  | 137, true ->  PA_FX_ERROR                of binstring (* [RFC6113] *)
  | 138, true ->  PA_ENCRYPTED_CHALLENGE     of binstring (* [RFC6113] *)
  | 147, true -> PA_PKINIT_KX                of binstring (* [RFC6112] *)
  | 148, true -> PA_PKU2U_NAME               of binstring (* [PKU2U] *)
  | 149, true -> Other_PA_DATA               of binstring (* FIXME *)
  | 165, true -> PA_SUPPORTED_ETYPES         of binstring (* [MS_KILE] *)
  | 166, true -> PA_EXTENDED_ERROR           of binstring (* [MS_KILE] *)
  | 167, true -> PA_PAC_OPTIONS              of pa_pac_options (* [MS_KILE] *)
  | _, false -> PA_NULL of binstring

let kerberos_oids = [
  "Diffie-Hellman Key Exchange" , [42;840;10046;2;1];
  "id-pkinit-san", [43;6;1;5;2;2];
  "id-pkinit-authData",  [43;6;1;5;2;3;1];
  "id-pkinit-DHKeyData",  [43;6;1;5;2;3;2];
  "id-pkinit-RKeyData",  [43;6;1;5;2;3;3];
  "id-pkinit-kdf-ah-sha1",  [43;6;1;5;2;3;6;1];
  "id-pkinit-kdf-ah-sha256",  [43;6;1;5;2;3;6;2];
  "id-pkinit-kdf-ah-sha512",  [43;6;1;5;2;3;6;3];
  "id-pkinit-kdf-ah-sha384",  [43;6;1;5;2;3;6;4];
]

let enc_fun_list = [
  [42;840;113549;3;7], "des-ede3-cbc", X509Basics.APT_DES3Params, md5sum ;
(*  "sha384", [96;840;1;101;3;4;2;2], sha384sum;
  "sha512", [96;840;1;101;3;4;2;3], sha512sum;
  "sha224", [96;840;1;101;3;4;2;4], sha224sum;*)
]


let _ =
  let register_oids (name, oid) = register_oid oid name in
  List.iter register_oids kerberos_oids;
  List.iter (X509Basics.populate_alg_directory Pkcs1.hash_funs) enc_fun_list
