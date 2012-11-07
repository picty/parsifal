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
(* Other fields *)
(****************)

asn1_alias x509_version = constructed [C_ContextSpecific, 0] der_integer

struct validity_content = {
(* TODO: "notBefore", AT_Custom (None, "time"), false, None;
  "notAfter",  AT_Custom (None, "time"), false, None; *)
  notBefore : der_object;
  notAfter : der_object
}
asn1_alias validity

asn1_alias issuerUniqueId = primitive [C_ContextSpecific, 1] der_bitstring
asn1_alias subjectUniqueId = primitive [C_ContextSpecific, 2] der_bitstring



(***********************)
(* tbs and Certificate *)
(***********************)

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
  signatureValue : der_bitstring
}
asn1_alias certificate [top]




(**************************)
(* Populating directories *)
(**************************)

let emailAddress_oid = [42;840;113549;1;9;1]

let rsaEncryption_oid = [42;840;113549;1;1;1]

let basicConstraints_oid = [85;29;19]

let _ =
  register_oid rsaEncryption_oid "rsaEncryption";
  Hashtbl.replace algorithmParamsType_directory rsaEncryption_oid APT_Null;
  Hashtbl.replace subjectPublicKeyType_directory rsaEncryption_oid (fun _ -> SPK_RSA);

  register_oid emailAddress_oid "emailAddress";
  Hashtbl.replace attributeValueType_directory emailAddress_oid AVT_IA5String;

  register_oid basicConstraints_oid "basicConstraints";
  Hashtbl.replace extensionType_directory basicConstraints_oid ET_BasicConstraints;
  ()


