open Parsifal
open PTypes
open Asn1Engine
open Asn1PTypes

(******************)
(* ATV, RD and DN *)
(******************)

(* TODO: Make the exhaustive meaningful *)
asn1_union directoryString [enrich; exhaustive; param len_cons] (UnparsedDirectoryString) =
  | C_Universal, false, T_T61String -> DS_T61String of
      length_constrained_container (len_cons) of der_octetstring_content (no_constraint)
  | C_Universal, false, T_PrintableString -> DS_PrintableString of
      length_constrained_container (len_cons) of der_octetstring_content (no_constraint)
  | C_Universal, false, T_UniversalString -> DS_UniversalString of
      length_constrained_container (len_cons) of der_octetstring_content (no_constraint)
  | C_Universal, false, T_UTF8String -> DS_UTF8String of
      length_constrained_container (len_cons) of der_octetstring_content (no_constraint)
  | C_Universal, false, T_BMPString -> DS_BMPString of
      length_constrained_container (len_cons) of der_octetstring_content (no_constraint)


type attributeValueType =
  | AVT_IA5String of length_constraint
  | AVT_PrintableString of length_constraint
  | AVT_DirectoryString of length_constraint
  | AVT_Anything

let attributeValueType_directory : (int list, attributeValueType) Hashtbl.t = Hashtbl.create 10

union attributeValue [enrich] (UnparsedAV of der_object) =
  | AVT_IA5String len_cons -> AV_IA5String of der_ia5string (len_cons)
  | AVT_PrintableString len_cons -> AV_PrintableString of der_printablestring (len_cons)
  | AVT_DirectoryString len_cons -> AV_DirectoryString of directoryString (len_cons)

struct atv_content = {
  attributeType : der_oid;
  attributeValue : attributeValue(hash_get attributeValueType_directory attributeType AVT_Anything)
}
asn1_alias atv

(* TODO: Rewrite this once to_string is generated automatically, at least for scalar types? *)
let string_of_atv_value = function
  | UnparsedAV { Asn1PTypes.a_content = String (s, _)}
  | AV_PrintableString s
  | AV_DirectoryString (DS_T61String s|DS_PrintableString s|
      DS_UniversalString s|DS_UTF8String s|DS_BMPString s)
  | AV_IA5String s -> quote_string s
  | _ -> "NON-STRING-VALUE"

let string_of_atv atv =
  "/" ^ (Asn1PTypes.short_string_of_oid atv.attributeType) ^ "=" ^ (string_of_atv_value atv.attributeValue)

(* TODO: Add constraints on set of [min, max] *)
asn1_alias rdn = set_of atv  (* min = 1 *)
asn1_alias distinguishedName = seq_of rdn

let string_of_distinguishedName dn =
  String.concat "" (List.map string_of_atv (List.flatten dn))

let print_distinguishedName ?indent:(indent="") ?name:(name="distinguishedName") dn =
  Printf.sprintf "%s%s: %s\n" indent name (string_of_distinguishedName dn)
  

(***********************)
(* AlgorithmIdentifier *)
(***********************)

type algorithmParamsType =
  | APT_Null
  | APT_DSAParams
  | APT_Unknown

let algorithmParamsType_directory : (int list, algorithmParamsType) Hashtbl.t = Hashtbl.create 10

union algorithmParams [enrich] (UnparsedParams of der_object) =
  | APT_Null -> NoParams of der_null
  | APT_DSAParams -> DSAParams of DSAKey.dsa_params

struct algorithmIdentifier_content = {
  algorithmId : der_oid;
  optional algorithmParams : algorithmParams(hash_get algorithmParamsType_directory algorithmId APT_Unknown)
}
asn1_alias algorithmIdentifier



(************************)
(* SubjectPublicKeyInfo *)
(************************)

type subjectPublicKeyType =
  | SPK_DSA of DSAKey.dsa_params
  | SPK_RSA
  | SPK_Unknown

let subjectPublicKeyType_directory : (int list, algorithmParams option -> subjectPublicKeyType) Hashtbl.t = Hashtbl.create 10
let subjectPublicKeyType_of_algo algo =
  try
    let f = Hashtbl.find subjectPublicKeyType_directory algo.algorithmId in
    f algo.algorithmParams
  with Not_found -> SPK_Unknown

union subjectPublicKey [enrich] (UnparsedPublicKey of der_object) =
  | SPK_DSA _params -> DSA of DSAKey.dsa_public_key
  | SPK_RSA -> RSA of RSAKey.rsa_public_key

struct subjectPublicKeyInfo_content = {
  algorithm : algorithmIdentifier;
  subjectPublicKey : bitstring_container of subjectPublicKey(subjectPublicKeyType_of_algo algorithm)
}
asn1_alias subjectPublicKeyInfo


(*************)
(* Signature *)
(*************)

type signatureType =
  | ST_DSA
  | ST_RSA
  | ST_Unknown

let signatureType_directory : (int list, algorithmParams option -> signatureType) Hashtbl.t = Hashtbl.create 10
let signatureType_of_algo algo =
  try
    let f = Hashtbl.find signatureType_directory algo.algorithmId in
    f algo.algorithmParams
  with Not_found -> ST_Unknown

union signature [enrich] (UnparsedSignature of der_object) =
  | ST_DSA -> DSASignature of DSAKey.dsa_signature
  | ST_RSA -> RSASignature of RSAKey.rsa_signature


(**************)
(* Extensions *)
(**************)

(* TODO? *)

(* OtherName ::= SEQUENCE { *)
(*      type-id    OBJECT IDENTIFIER, *)
(*      value      [0] EXPLICIT ANY DEFINED BY type-id } *)

(* ORAddress ::= SEQUENCE { *)
(*    built-in-standard-attributes BuiltInStandardAttributes, *)
(*    built-in-domain-defined-attributes *)
(*                    BuiltInDomainDefinedAttributes OPTIONAL, *)
(*    -- see also teletex-domain-defined-attributes *)
(*    extension-attributes ExtensionAttributes OPTIONAL } *)

(* EDIPartyName ::= SEQUENCE { *)
(*      nameAssigner            [0]     DirectoryString OPTIONAL, *)
(*      partyName               [1]     DirectoryString } *)

(* TODO: Make the exhaustive meaningful *)
asn1_union generalName [enrich; exhaustive] (UnparsedGeneralName) =
  | (C_ContextSpecific, true, T_Unknown 0) as h -> OtherName of der_object_content (h)
  | C_ContextSpecific, false, T_Unknown 1 -> Rfc822Name of der_printable_octetstring_content (no_constraint) (* IA5 *)
  | C_ContextSpecific, false, T_Unknown 2 -> DNSName of der_printable_octetstring_content (no_constraint) (* IA5 *)
  | (C_ContextSpecific, true, T_Unknown 3) as h -> X400Address of der_object_content (h)
  | C_ContextSpecific, true, T_Unknown 4 -> DirectoryName of distinguishedName
  | (C_ContextSpecific, true, T_Unknown 5) as h -> EDIPartyName of der_object_content (h)
  | C_ContextSpecific, false, T_Unknown 6 -> UniformResourceIdentifier of der_printable_octetstring_content (no_constraint) (* IA5 *)
  | C_ContextSpecific, false, T_Unknown 7 -> IPAddress of der_octetstring_content (no_constraint)
  | C_ContextSpecific, false, T_Unknown 8 -> RegisteredID of der_oid_content
asn1_alias generalNames = seq_of generalName

(* Authority Key Identifier *)
(* TODO: add constraint on [1] and [2] that MUST both be present or absent *)
struct authorityKeyIdentifier_content = {
  optional keyIdentifier : asn1 [(C_ContextSpecific, false, T_Unknown 0)] of binstring;
  optional authorityCertIssuer : asn1 [(C_ContextSpecific, true, T_Unknown 1)] of (list of generalName);
  optional authorityCertSerialNumber : asn1 [(C_ContextSpecific, false, T_Unknown 2)] of der_integer_content
}
asn1_alias authorityKeyIdentifier


(* Key Usage *)
let keyUsage_values = [|
  "digitalSignature";
  "nonRepudiation";
  "keyEncipherment";
  "dataEncipherment";
  "keyAgreement";
  "keyCertSign";
  "cRLSign";
  "encipherOnly";
  "decipherOnly"
|]


(* Basic Constraints *)
struct basicConstraints_content = {
  optional cA : der_boolean;
  optional pathLenConstraint : der_smallint
}
asn1_alias basicConstraints


(* Extended Key Usage *)
asn1_alias extendedKeyUsage = seq_of der_oid


(* Certificate Policies *)

(* TODO: Make the exhaustive meaningful *)
asn1_union displayText [enrich; exhaustive] (UnparsedDisplayText) =
  | C_Universal, false, T_IA5String -> DT_IA5String of der_octetstring_content (no_constraint)
  | C_Universal, false, T_VisibleString -> DT_VisibleString of der_octetstring_content (no_constraint)
  | C_Universal, false, T_UTF8String -> DT_UTF8String of der_octetstring_content (no_constraint)
  | C_Universal, false, T_BMPString -> DT_BMPString of der_octetstring_content (no_constraint)

struct noticeReference_content = {
  organization : displayText;
  noticeNumbers : asn1 [(C_Universal, true, T_Sequence)] of der_integer
}
asn1_alias noticeReference

struct userNotice_content = {
  optional noticeRef : noticeReference;
  optional explicitText : displayText
}
asn1_alias userNotice

union policyQualifier [enrich] (UnparsedQualifier of der_object) =
  | "id-qt-cps" -> CPSuri of der_ia5string(NoConstraint)
  | "id-qt-unotice" -> UserNotice of userNotice

struct policyQualifierInfo_content = {
  policyQualifierId : der_oid;
  qualifier : policyQualifier(hash_get oid_directory policyQualifierId "")
}
asn1_alias policyQualifierInfo
asn1_alias policyQualifiers = seq_of policyQualifierInfo (* TODO: 1..MAX *)

struct policyInformation_content = {
  policyIdentifer : der_oid;
  optional policyQualifiers : policyQualifiers
}
asn1_alias policyInformation
asn1_alias certificatePolicies = seq_of policyInformation (* 1..MAX *)


(* CRL Distribution Points *)

(* TODO: Make the exhaustive meaningful *)
asn1_union distributionPointName [enrich; exhaustive] (UnparsedDistributionPointName) =
  | C_ContextSpecific, true, T_Unknown 0 -> FullName of (list of generalName)
  | C_ContextSpecific, true, T_Unknown 1 -> NameRelativeToCRLIssuer of (list of atv)

let reasonFlags_values = [|
  "unused";
  "keyCompromise";
  "caCompromise";
  "affiliationChanged";
  "superseded";
  "cessationOfOperation";
  "certificateHold";
  "privilegeWithdrawn";
  "aaCompromise"
|]

(* TODO: Add structural check: at least 0 or 2 should be present *)
struct distributionPoint_content = {
  optional distributionPoint : asn1 [(C_ContextSpecific, true, T_Unknown 0)] of distributionPointName;
  optional reasons : asn1 [(C_ContextSpecific, true, T_Unknown 1)] of der_enumerated_bitstring_content[reasonFlags_values];
  optional crlIssuer : asn1 [(C_ContextSpecific, true, T_Unknown 2)] of (list of generalName)
}

asn1_alias distributionPoint
asn1_alias crlDistributionPoints = seq_of distributionPoint (* TODO: 1 .. MAX *)


(* NameConstraints *)

struct generalSubtree_content = {
  gst_base : generalName;
  optional gst_minimum : asn1 [(C_ContextSpecific, true, T_Unknown 0)] of der_integer_content;
  optional gst_maximum : asn1 [(C_ContextSpecific, true, T_Unknown 1)] of der_integer_content
}
asn1_alias generalSubtree
asn1_alias generalSubtrees = seq_of generalSubtree (* TODO: 1 .. MAX *)

(* TODO: Add structural constraint (0 or 1 must be present) *)
struct nameConstraints_content = {
  optional permittedSubtrees : asn1 [(C_ContextSpecific, true, T_Unknown 0)] of generalSubtrees;
  optional excludedSubtrees : asn1 [(C_ContextSpecific, true, T_Unknown 1)] of generalSubtrees
}
asn1_alias nameConstraints


(* Authority Information Access *)

struct accessDescription_content = {
  accessMethod : der_oid;
  accessLocation : generalName
}
asn1_alias accessDescription
asn1_alias authorityInfoAccess = seq_of accessDescription (* TODO: 1 .. MAX *)


union extnValue [enrich] (UnparsedExtension of binstring) =
  | "authorityKeyIdentifier" -> AuthorityKeyIdentifier of authorityKeyIdentifier
  | "subjectKeyIdentifier" -> SubjectKeyIdentifier of der_octetstring
  | "keyUsage" -> KeyUsage of der_enumerated_bitstring[keyUsage_values]
  | "basicConstraints" -> BasicConstraints of basicConstraints
  | "extendedKeyUsage" -> ExtendedKeyUsage of extendedKeyUsage
  | "certificatePolicies" -> CertificatePolicies of certificatePolicies
  | "crlDistributionPoints" -> CRLDistributionPoints of crlDistributionPoints
  | "nameConstraints" -> NameConstraints of nameConstraints
  | "subjectAlternativeName" -> SubjectAlternativeName of generalNames
  | "authorityInfoAccess" -> AuthorityInfoAccess of authorityInfoAccess

struct extension_content = {
  extnID : der_oid;
  optional critical : der_boolean;
  extnValue : octetstring_container of extnValue(hash_get oid_directory extnID "")
}



(* let print_extension_content ?indent:(indent="") ?name:(name="") ext = *)
(*   let real_name = *)
(*     if name = "" *)
(*     then Asn1PTypes.string_of_oid ext.extnID *)
(*     else name *)
(*   in *)
(*   let critical_str = if pop_opt false ext.critical then " (critical)" else "" in *)
(*   let value_str = print_extnValue ext.extnValue in *)
(*   Printf.sprintf "%s%s%s: %s\n" indent real_name critical_str value_str *)

asn1_alias extension
asn1_alias extension_list = seq_of extension (* TODO: min = 1 *)




(************)
(* Validity *)
(************)

(* TODO: this "exhaustive" should produce a warning� *)
asn1_union der_time [enrich; exhaustive] (UnparsedTime) =
  | (C_Universal, false, T_UTCTime) -> UTCTime of der_utc_time_content
  | (C_Universal, false, T_GeneralizedTime) -> GeneralizedTime of der_generalized_time_content

let string_of_der_time = function
  | UTCTime t | GeneralizedTime t -> string_of_time_content t
  | UnparsedTime o -> raise (ParsingException (CustomException "UnparsedTime", []))

struct validity_content = {
  notBefore : der_time;
  notAfter : der_time
}
asn1_alias validity




(***********************)
(* tbs and Certificate *)
(***********************)

asn1_alias issuerUniqueId = primitive [C_ContextSpecific, 1] der_bitstring
asn1_alias subjectUniqueId = primitive [C_ContextSpecific, 2] der_bitstring

struct tbsCertificate_content = {
  optional version : asn1 [(C_ContextSpecific, true, T_Unknown 0)] of der_smallint;
  serialNumber : der_integer;
  signature : algorithmIdentifier;
  parse_checkpoint position_before_issuer : save_offset;
  issuer : distinguishedName;
  parse_field issuer_raw : raw_value(position_before_issuer);
  validity : validity;
  parse_checkpoint position_before_subject : save_offset;
  subject : distinguishedName;
  parse_field subject_raw : raw_value(position_before_subject);
  subjectPublicKeyInfo : subjectPublicKeyInfo;
  optional issuerUniqueId : asn1 [(C_ContextSpecific, false, T_Unknown 1)] of der_bitstring_content;
  optional subjectUniqueId : asn1 [(C_ContextSpecific, false, T_Unknown 2)] of der_bitstring_content;
  optional extensions : asn1 [(C_ContextSpecific, true, T_Unknown 3)] of extension_list
}
asn1_alias tbsCertificate

struct certificate_content = {
  parse_checkpoint position_before_tbs : save_offset;
  tbsCertificate : tbsCertificate;
  parse_field tbsCertificate_raw : raw_value(position_before_tbs);
  signatureAlgorithm : algorithmIdentifier;
  signatureValue : bitstring_container of signature(signatureType_of_algo signatureAlgorithm)
}
asn1_alias certificate [top]




(**************************)
(* Populating directories *)
(**************************)

let attribute_value_types = [
  [85; 4; 41], "name", None, AVT_DirectoryString(AtMost 32768);
  [85; 4; 4], "surname", None, AVT_DirectoryString(AtMost 32768);
  [85; 4; 42], "givenName", None, AVT_DirectoryString(AtMost 32768);
  [85; 4; 43], "initials", None, AVT_DirectoryString(AtMost 32768);
  [85; 4; 44], "generationQualifier", None, AVT_DirectoryString(AtMost 32768);

  [85; 4; 3], "commonName", Some "CN", AVT_DirectoryString(AtMost 64);
  [85; 4; 7], "localityName", Some "L", AVT_DirectoryString(AtMost 128);
  [85; 4; 8], "stateOrProvinceName", Some "S", AVT_DirectoryString(AtMost 128);
  [85; 4; 10], "organizationName", Some "O", AVT_DirectoryString(AtMost 64);
  [85; 4; 11], "organizationalUnitName", Some "OU", AVT_DirectoryString(AtMost 64);
  [85; 4; 12], "title", None, AVT_DirectoryString(AtMost 64);
  [85; 4; 46], "dnQualifier", None, AVT_PrintableString(NoConstraint);
  [85; 4; 6], "countryName", Some "C", AVT_PrintableString(AtMost 2);
  [85; 4; 5], "serialNumber", Some "SN", AVT_PrintableString(AtMost 64);
  [85; 4; 65], "pseudonym", None, AVT_DirectoryString(AtMost 128);

  [9; 2342; 19200300; 100; 1; 25], "domainComponent", Some "dc", AVT_IA5String(NoConstraint);
  [42;840;113549;1;9;1], "emailAddress", None, AVT_IA5String(AtMost 255)
]


let dsa_spk_of_param = function
  | Some (DSAParams dp) -> SPK_DSA dp
  | _ -> SPK_Unknown

let public_key_types = [
  [42;840;113549;1;1;1], "rsaEncryption", APT_Null, (fun _ -> SPK_RSA);
  [42;840;10040;4;1], "dsa", APT_DSAParams, dsa_spk_of_param
]

let signature_types = [
  [42;840;113549;1;1;2], "md2WithRSAEncryption", APT_Null, (fun _ -> ST_RSA);
  [42;840;113549;1;1;3], "md4WithRSAEncryption", APT_Null, (fun _ -> ST_RSA);
  [42;840;113549;1;1;4], "md5WithRSAEncryption", APT_Null, (fun _ -> ST_RSA);
  [42;840;113549;1;1;5], "sha1WithRSAEncryption", APT_Null, (fun _ -> ST_RSA);
  [42;840;113549;1;1;11], "sha256WithRSAEncryption", APT_Null, (fun _ -> ST_RSA);
  [42;840;113549;1;1;12], "sha384WithRSAEncryption", APT_Null, (fun _ -> ST_RSA);
  [42;840;113549;1;1;13], "sha512WithRSAEncryption", APT_Null, (fun _ -> ST_RSA);
  [42;840;113549;1;1;14], "sha224WithRSAEncryption", APT_Null, (fun _ -> ST_RSA);
  [42;840;10040;4;3], "dsaWithSha1", APT_Null, (fun _ -> ST_DSA);
  [96;840;1;101;3;4;3;1], "dsaWithSha224", APT_Null, (fun _ -> ST_DSA);
  [96;840;1;101;3;4;3;2], "dsaWithSha256", APT_Null, (fun _ -> ST_DSA);
]

let extension_types = [
  [85;29;1], "authorityKeyIdentifier";
  [85;29;14], "subjectKeyIdentifier";
  [85;29;15], "keyUsage";
  [85;29;17], "subjectAlternativeName";
  [85;29;19], "basicConstraints";
  [85;29;30], "nameConstraints";
  [85;29;31], "crlDistributionPoints";
  [85;29;32], "certificatePolicies";
  [85;29;35], "authorityKeyIdentifier";
  [85;29;37], "extendedKeyUsage";
  [43;6;1;5;5;7;1;1], "authorityInfoAccess";
]


let other_oids = [
  (* Prefixes *)
  [43;6;1;5;5;7], "id-pkix";
  [43;6;1;5;5;7;1], "id-pe";
  [43;6;1;5;5;7;2], "id-qt";
  [43;6;1;5;5;7;3], "id-kp";
  [43;6;1;5;5;7;48], "id-ad";
  [85;29], "id-ce";

  [85;29;37;0], "anyExtendedKeyUsage";
  [43;6;1;5;5;7;3;1], "serverAuth";
  [43;6;1;5;5;7;3;2], "clientAuth";
  [43;6;1;5;5;7;3;3], "codeSigning";
  [43;6;1;5;5;7;3;4], "emailProtection";
  [43;6;1;5;5;7;3;8], "timeStamping";
  [43;6;1;5;5;7;3;9], "OCSPSigning";

  [85;29;32;0], "anyPolicy";
  [43;6;1;5;5;7;2;1], "id-qt-cps";
  [43;6;1;5;5;7;2;2], "id-qt-unotice";

  [43;6;1;5;5;7;48;1], "id-ad-ocsp";
  [43;6;1;5;5;7;48;2], "id-ad-caIssuers";
]


let populate_atv_directory (id, name, short, value) =
  register_oid ~short:short id name;
  Hashtbl.replace attributeValueType_directory id value

let populate_alg_directory dir (id, name, algParam, value) =
  register_oid id name;
  Hashtbl.replace algorithmParamsType_directory id algParam;
  Hashtbl.replace dir id value


let _ =
  List.iter (populate_atv_directory) attribute_value_types;
  List.iter (fun (id, name) -> register_oid id name) extension_types;
  List.iter (fun (id, name) -> register_oid id name) other_oids;
  List.iter (populate_alg_directory subjectPublicKeyType_directory) public_key_types;
  List.iter (populate_alg_directory signatureType_directory) signature_types;  
  ()


