open Parsifal
open Asn1Engine
open Asn1PTypes

(******************)
(* ATV, RD and DN *)
(******************)

type directoryString = asn1_tag * string

let parse_directoryString input =
  let aux h new_input = match h with
    | (C_Universal, false,
       (T_T61String|T_PrintableString|T_UniversalString|
        T_UTF8String|T_BMPString as t)) ->
      t, parse_der_octetstring_content no_constraint new_input
    | h -> fatal_error (UnexpectedHeader (h, None)) input
  in advanced_der_parse aux input

let dump_directoryString (t, s) =
  produce_der_object (C_Universal, false, t) (fun x -> x) s

let print_directoryString ?indent:(indent="") ?name:(name="directoryString") (_, s) =
  Printf.sprintf "%s%s: %s\n" indent name s



type attributeValueType =
  | AVT_IA5String of int option
  | AVT_PrintableString of int option
  | AVT_DirectoryString of int option
  | AVT_Anything

let attributeValueType_directory : (int list, attributeValueType) Hashtbl.t = Hashtbl.create 10

(* TODO: Handle length constraints on strings *)
union attributeValue [enrich] (UnparsedAV of der_object) =
  | AVT_IA5String _ -> AV_IA5String of der_ia5string
  | AVT_PrintableString _ -> AV_PrintableString of der_printablestring
  | AVT_DirectoryString _ -> AV_DirectoryString of directoryString

struct atv_content = {
  attributeType : der_oid;
  attributeValue : attributeValue(hash_get attributeValueType_directory attributeType AVT_Anything)
}
asn1_alias atv

let string_of_atv_value = function
  | UnparsedAV { Asn1PTypes.a_content = String (s, _)}
  | AV_PrintableString s
  | AV_DirectoryString (_, s)
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
  | APT_Unknown

let algorithmParamsType_directory : (int list, algorithmParamsType) Hashtbl.t = Hashtbl.create 10

union algorithmParams [enrich] (UnparsedParams of der_object) =
  | APT_Null -> NoParams of der_null

struct algorithmIdentifier_content = {
  algorithmId : der_oid;
  optional algorithmParams : algorithmParams(hash_get algorithmParamsType_directory algorithmId APT_Unknown)
}
asn1_alias algorithmIdentifier



(************************)
(* SubjectPublicKeyInfo *)
(************************)

type subjectPublicKeyType =
  | SPK_RSA
  | SPK_Unknown

let subjectPublicKeyType_directory : (int list, algorithmParams option -> subjectPublicKeyType) Hashtbl.t = Hashtbl.create 10
let subjectPublicKeyType_of_algo algo =
  try
    let f = Hashtbl.find subjectPublicKeyType_directory algo.algorithmId in
    f algo.algorithmParams
  with Not_found -> SPK_Unknown

union subjectPublicKey [enrich] (UnparsedPublicKey of der_object) =
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
  | ST_RSA
  | ST_Unknown

let signatureType_directory : (int list, algorithmParams option -> signatureType) Hashtbl.t = Hashtbl.create 10
let signatureType_of_algo algo =
  try
    let f = Hashtbl.find signatureType_directory algo.algorithmId in
    f algo.algorithmParams
  with Not_found -> ST_Unknown

union signature [enrich] (UnparsedSignature of der_object) =
  | ST_RSA -> RSASignature of der_bitstring


(**************)
(* Extensions *)
(**************)

(* Authority Key Identifier *)
(* TODO: add constraint on [1] and [2] that MUST both be present or absent *)
struct authorityKeyIdentifier_content = {
  optional keyIdentifier : asn1 [(C_ContextSpecific, false, T_Unknown 0)] of binstring;
  optional authorityCertIssuerUNPARSED : asn1 [(C_ContextSpecific, true, T_Unknown 1)] of (list of der_object); (* TODO: GeneralName *)
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

(* TODO: Rewrite this with asn1_union *)
type displayText = asn1_tag * string

let parse_displayText input =
  let aux h new_input = match h with
    | (C_Universal, false,
       (T_IA5String|T_VisibleString|
        T_UTF8String|T_BMPString as t)) ->
      t, parse_der_octetstring_content no_constraint new_input
    | h -> fatal_error (UnexpectedHeader (h, None)) input
  in advanced_der_parse aux input

let dump_displayText (t, s) =
  produce_der_object (C_Universal, false, t) (fun x -> x) s

let print_displayText ?indent:(indent="") ?name:(name="displayText") (_, s) =
  Printf.sprintf "%s%s: %s\n" indent name s

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
  | "id-qt-cps" -> CPSuri of der_ia5string
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

(* TODO *)
(* DistributionPointName ::= CHOICE { *)
(*      fullName                [0]     GeneralNames, *)
(*      nameRelativeToCRLIssuer [1]     RelativeDistinguishedName } *)
alias distributionPointName = der_object

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
  optional distributionPointUNPARSED : asn1 [(C_ContextSpecific, true, T_Unknown 0)] of distributionPointName;
  optional reasons : asn1 [(C_ContextSpecific, true, T_Unknown 1)] of der_enumerated_bitstring_content[reasonFlags_values];
  optional crlIssuerUNPARSED : asn1 [(C_ContextSpecific, true, T_Unknown 2)] of (list of der_object) (* TODO: GeneralName *)
}

asn1_alias distributionPoint
asn1_alias crlDistributionPoints = seq_of distributionPoint (* TODO: 1.. MAX *)



union extnValue [enrich] (UnparsedExtension of binstring) =
  | "authorityKeyIdentifier" -> AuthorityKeyIdentifier of authorityKeyIdentifier
  | "subjectKeyIdentifier" -> SubjectKeyIdentifier of der_octetstring
  | "keyUsage" -> KeyUsage of der_enumerated_bitstring[keyUsage_values]
  | "basicConstraints" -> BasicConstraints of basicConstraints
  | "extendedKeyUsage" -> ExtendedKeyUsage of extendedKeyUsage
  | "certificatePolicies" -> CertificatePolicies of certificatePolicies
  | "crlDistributionPoints" -> CRLDistributionPoints of crlDistributionPoints

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

type time =
  | UTCTime of (int * int * int * int * int * int)
  | GeneralizedTime of (int * int * int * int * int * int)

let parse_time input =
  let aux h new_input = match h with
    | (C_Universal, false, T_UTCTime) ->
      UTCTime (parse_der_processed_string_content utc_time_constraint new_input)
    | (C_Universal, false, T_GeneralizedTime) ->
      GeneralizedTime (parse_der_processed_string_content generalized_time_constraint new_input)
    | _ -> fatal_error InvalidUTCTime input
  in
  advanced_der_parse aux input

let dump_time time =
  let aux isGen (y, m, d, yy, mm, ss) =
    let l = if isGen then 4 else 2 in
    Printf.sprintf "%*.*d%2.2d%2.2d%2.2d%2.2d%2.2dZ" l l y m d yy mm ss
  in
  match time with
  | UTCTime t ->
    produce_der_object (C_Universal, false, T_UTCTime) (fun x -> x) (aux false t)
  | GeneralizedTime t ->
    produce_der_object (C_Universal, false, T_UTCTime) (fun x -> x) (aux true t)

let string_of_time time =
  let aux isGen (y, m, d, yy, mm, ss) =
    let l = if isGen then 4 else 2 in
    Printf.sprintf "%*.*d-%2.2d-%2.2d %2.2d:%2.2d:%2.2d UTC" l l y m d yy mm ss
  in
  match time with
    | UTCTime t -> aux false t
    | GeneralizedTime t -> aux true t

let print_time ?indent:(indent="") ?name:(name="time") time =
  Printf.sprintf "%s%s: %s\n" indent name (string_of_time time)

struct validity_content = {
  notBefore : time;
  notAfter : time
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
  signatureValue : signature(signatureType_of_algo signatureAlgorithm)
}
asn1_alias certificate [top]




(**************************)
(* Populating directories *)
(**************************)

let attribute_value_types = [
  [85; 4; 41], "name", None, AVT_DirectoryString(Some 32768);
  [85; 4; 4], "surname", None, AVT_DirectoryString(Some 32768);
  [85; 4; 42], "givenName", None, AVT_DirectoryString(Some 32768);
  [85; 4; 43], "initials", None, AVT_DirectoryString(Some 32768);
  [85; 4; 44], "generationQualifier", None, AVT_DirectoryString(Some 32768);

  [85; 4; 3], "commonName", Some "CN", AVT_DirectoryString(Some 64);
  [85; 4; 7], "localityName", Some "L", AVT_DirectoryString(Some 128);
  [85; 4; 8], "stateOrProvinceName", Some "S", AVT_DirectoryString(Some 128);
  [85; 4; 10], "organizationName", Some "O", AVT_DirectoryString(Some 64);
  [85; 4; 11], "organizationalUnitName", Some "OU", AVT_DirectoryString(Some 64);
  [85; 4; 12], "title", None, AVT_DirectoryString(Some 64);
  [85; 4; 46], "dnQualifier", None, AVT_PrintableString(None);
  [85; 4; 6], "countryName", Some "C", AVT_PrintableString(Some 2);
  [85; 4; 5], "serialNumber", Some "SN", AVT_PrintableString(Some 64);
  [85; 4; 65], "pseudonym", None, AVT_DirectoryString(Some 128);

  [9; 2342; 19200300; 100; 1; 25], "domainComponent", Some "dc", AVT_IA5String(None);
  [42;840;113549;1;9;1], "emailAddress", None, AVT_IA5String(Some 255)
]


let public_key_types = [
  [42;840;113549;1;1;1], "rsaEncryption", APT_Null, (fun _ -> SPK_RSA);
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
]

let extension_types = [
  [85;29;35], "authorityKeyIdentifier";
  [85;29;14], "subjectKeyIdentifier";
  [85;29;15], "keyUsage";
  [85;29;19], "basicConstraints";
  [85;29;37], "extendedKeyUsage";
  [85;29;32], "certificatePolicies";
  [85;29;31], "crlDistributionPoints";
]

let policyQualifier_ids = [
  [43;6;1;5;5;7;2;1], "id-qt-cps";
  [43;6;1;5;5;7;2;2], "id-qt-unotice";
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
  List.iter (fun (id, name) -> register_oid id name) policyQualifier_ids;
  List.iter (fun (id, name) -> register_oid id name) other_oids;
  List.iter (populate_alg_directory subjectPublicKeyType_directory) public_key_types;
  List.iter (populate_alg_directory signatureType_directory) signature_types;  
  ()


