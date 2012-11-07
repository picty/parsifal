open Parsifal
open Asn1PTypes

(******************)
(* ATV, RD and DN *)
(******************)

type attributeValueType =
  | AVT_IA5String
  | AVT_Anything

let attributeValueType_directory : (int list, attributeValueType) Hashtbl.t = Hashtbl.create 10

(* TODO: Handle DirectoryString / Constraints on strings *)
union attributeValue [enrich] (UnparsedAV of der_object) =
  | AVT_IA5String -> AV_IA5String of der_ia5string

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
asn1_alias distinguished_name = seq_of rdn



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

type extensionType =
  | ET_BasicConstraints
  | ET_Unknown

let extensionType_directory : (int list, extensionType) Hashtbl.t = Hashtbl.create 10

(* Basic Constraints *)
struct basic_constraints_content = {
  optional cA : der_boolean;
  optional pathLenConstraint : der_smallint
}
asn1_alias basic_constraints

union extnValue [enrich] (UnparsedExtension of der_object) =
  | ET_BasicConstraints -> BasicConstraints of basic_constraints



(* TODO: Make extnValue depend on extnID, and have it enrichable *)
struct extension_content = {
  extnID : der_oid;
  optional critical : der_boolean;
  extnValue : octetstring_container of extnValue(hash_get extensionType_directory extnID ET_Unknown)
}
asn1_alias extension

asn1_alias extension_list = seq_of extension (* TODO: min = 1 *)
asn1_alias extensions = constructed [C_ContextSpecific, 3] extension_list




(****************)
(* Validity *)
(****************)

(* TODO: Think of a way to factor this? *)

type time =
  | UTCTime of (int * int * int * int * int * int)
  | GeneralizedTime of (int * int * int * int * int * int)

let print_time ?indent:(indent="") ?name:(name="time") time =
  let aux isGen (y, m, d, yy, mm, ss) =
    let l = if isGen then 4 else 2 in
    Printf.sprintf "%*.*d-%2.2d-%2.2d %2.2d:%2.2d:%2.2d UTC" l l y m d yy mm ss
  in
  let s = match time with
    | UTCTime t -> aux false t
    | GeneralizedTime t -> aux true t
  in
  print_printablestring ~indent:indent ~name:name s

let parse_time input =
  let c, isC, t = Asn1Engine.extract_der_header input in
  let len = Asn1Engine.extract_der_length input in
  let new_input = get_in input (Asn1Engine.print_header (c, isC, t)) len in
  let res = match c, isC, t with
    | (Asn1Engine.C_Universal, false, Asn1Engine.T_UTCTime) ->
      UTCTime (parse_der_processed_string_content utc_time_constraint new_input)
    | (Asn1Engine.C_Universal, false, Asn1Engine.T_GeneralizedTime) ->
      GeneralizedTime (parse_der_processed_string_content generalized_time_constraint new_input)
    | _ -> Asn1Engine.fatal_error Asn1Engine.InvalidUTCTime input
  in
  get_out input new_input;
  print_endline (print_time res);
  res

let dump_time time =
  let aux isGen (y, m, d, yy, mm, ss) =
    let l = if isGen then 4 else 2 in
    Printf.sprintf "%*.*d%2.2d%2.2d%2.2d%2.2d%2.2dZ" l l y m d yy mm ss
  in
  match time with
  | UTCTime t ->
    Asn1Engine.produce_der_object (Asn1Engine.C_Universal, false, Asn1Engine.T_UTCTime) (fun x -> x) (aux false t)
  | GeneralizedTime t ->
    Asn1Engine.produce_der_object (Asn1Engine.C_Universal, false, Asn1Engine.T_UTCTime) (fun x -> x) (aux true t)

struct validity_content = {
  notBefore : time;
  notAfter : time
}
asn1_alias validity




(***********************)
(* tbs and Certificate *)
(***********************)

asn1_alias x509_version = constructed [C_ContextSpecific, 0] der_integer
asn1_alias issuerUniqueId = primitive [C_ContextSpecific, 1] der_bitstring
asn1_alias subjectUniqueId = primitive [C_ContextSpecific, 2] der_bitstring

struct tbsCertificate_content = {
  optional version : x509_version;
  serialNumber : der_integer;
  signature : algorithmIdentifier;
  issuer : distinguished_name;
  validity : validity;
  subject : distinguished_name;
  subjectPublicKeyInfo : subjectPublicKeyInfo;
  optional issuerUniqueId : issuerUniqueId;
  optional subjectUniqueId : subjectUniqueId;
  optional extensions : extensions
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
  [42;840;113549;1;9;1], "emailAddress", AVT_IA5String
]

let public_key_types = [
  [42;840;113549;1;1;1], "rsaEncryption", APT_Null, (fun _ -> SPK_RSA);
]

let signature_types = [
  [42;840;113549;1;1;11], "sha256WithRSAEncryption", APT_Null, (fun _ -> ST_RSA);
]

let extension_types = [
  [85;29;19], "basicConstraints", ET_BasicConstraints;
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
  List.iter (populate_simple_directory extensionType_directory) extension_types;
  List.iter (populate_alg_directory subjectPublicKeyType_directory) public_key_types;
  List.iter (populate_alg_directory signatureType_directory) signature_types;  
  ()


