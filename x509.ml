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

(* TODO: This should be improved *)
let string_of_atv atv = match atv.attributeValue with
  | UnparsedAV { Asn1PTypes.a_content = String (s, _)}
  | AV_IA5String s -> "\"" ^ s ^ "\""
  | _ -> "\"\""

(* TODO: Add constraints on set of [min, max] *)
asn1_alias rdn = set_of atv  (* min = 1 *)
asn1_alias distinguishedName = seq_of rdn



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

union extnValue [enrich] (UnparsedExtension of binstring) =
  | "authorityKeyIdentifier" -> AuthorityKeyIdentifier of authorityKeyIdentifier
  | "subjectKeyIdentifier" -> SubjectKeyIdentifier of der_octetstring
  | "keyUsage" -> KeyUsage of der_enumerated_bitstring[keyUsage_values]
  | "basicConstraints" -> BasicConstraints of basicConstraints

struct extension_content = {
  extnID : der_oid;
  optional critical : der_boolean;
  extnValue : octetstring_container of extnValue(hash_get oid_directory extnID "")
}
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

let print_time ?indent:(indent="") ?name:(name="time") time =
  let aux isGen (y, m, d, yy, mm, ss) =
    let l = if isGen then 4 else 2 in
    Printf.sprintf "%*.*d-%2.2d-%2.2d %2.2d:%2.2d:%2.2d UTC" l l y m d yy mm ss
  in
  let s = match time with
    | UTCTime t -> aux false t
    | GeneralizedTime t -> aux true t
  in
  Printf.sprintf "%s%s: %s\n" indent name s

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
  issuer : distinguishedName;
  validity : validity;
  subject : distinguishedName;
  subjectPublicKeyInfo : subjectPublicKeyInfo;
  optional issuerUniqueId : asn1 [(C_ContextSpecific, false, T_Unknown 1)] of der_bitstring_content;
  optional subjectUniqueId : asn1 [(C_ContextSpecific, false, T_Unknown 2)] of der_bitstring_content;
  optional extensions : asn1 [(C_ContextSpecific, true, T_Unknown 3)] of extension_list
}
asn1_alias tbsCertificate

struct certificate_content = {
  tbsCertificate : tbsCertificate;
  signatureAlgorithm : algorithmIdentifier;
  signatureValue : signature(signatureType_of_algo signatureAlgorithm)
}
asn1_alias certificate [top]




(**************************)
(* Populating directories *)
(**************************)

let attribute_value_types = [
  [85; 4; 41], "name", AVT_DirectoryString(Some 32768);
  [85; 4; 4], "surname", AVT_DirectoryString(Some 32768);
  [85; 4; 42], "givenName", AVT_DirectoryString(Some 32768);
  [85; 4; 43], "initials", AVT_DirectoryString(Some 32768);
  [85; 4; 44], "generationQualifier", AVT_DirectoryString(Some 32768);

  [85; 4; 3], "commonName", AVT_DirectoryString(Some 64);
  [85; 4; 7], "localityName", AVT_DirectoryString(Some 128);
  [85; 4; 8], "stateOrProvinceName", AVT_DirectoryString(Some 128);
  [85; 4; 10], "organizationName", AVT_DirectoryString(Some 64);
  [85; 4; 11], "organizationalUnitName", AVT_DirectoryString(Some 64);
  [85; 4; 12], "title", AVT_DirectoryString(Some 64);
  [85; 4; 46], "dnQualifier", AVT_PrintableString(None);
  [85; 4; 6], "countryName", AVT_PrintableString(Some 2);
  [85; 4; 5], "serialNumber", AVT_PrintableString(Some 64);
  [85; 4; 65], "pseudonym", AVT_DirectoryString(Some 128);

  [9; 2342; 19200300; 100; 1; 25], "domainComponent", AVT_IA5String(None);
  [42;840;113549;1;9;1], "emailAddress", AVT_IA5String(Some 255)
]


let public_key_types = [
  [42;840;113549;1;1;1], "rsaEncryption", APT_Null, (fun _ -> SPK_RSA);
]

let signature_types = [
  [42;840;113549;1;1;2], "md2WithRSAEncryption", APT_Null, (fun _ -> ST_RSA);
  [42;840;113549;1;1;3], "md4WithRSAEncryption", APT_Null, (fun _ -> ST_RSA);
  [42;840;113549;1;1;4], "md5WithRSAEncryption", APT_Null, (fun _ -> ST_RSA);
  [42;840;113549;1;1;5], "sha1-with-rsa-signature", APT_Null, (fun _ -> ST_RSA);
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
]

let populate_simple_directory dir (id, name, value) =
  register_oid id name;
  Hashtbl.replace dir id value

let populate_alg_directory dir (id, name, algParam, value) =
  register_oid id name;
  Hashtbl.replace algorithmParamsType_directory id algParam;
  Hashtbl.replace dir id value


let _ =
  List.iter (populate_simple_directory attributeValueType_directory) attribute_value_types;
  List.iter (fun (id, name) -> register_oid id name) extension_types;
  List.iter (populate_alg_directory subjectPublicKeyType_directory) public_key_types;
  List.iter (populate_alg_directory signatureType_directory) signature_types;  
  ()


