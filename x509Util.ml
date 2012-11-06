open Common
open Asn1Engine
open Parsifal
open Asn1PTypes


(* AlgorithmIdentifier *)
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


(* SubjectPublicKeyInfo *)
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




(* register the OId in a general table *)
let rsaEncryption_oid = [42;840;113549;1;1;1]

let _ =
  register_oid rsaEncryption_oid "rsaEncryption";
  Hashtbl.replace algorithmParamsType_directory rsaEncryption_oid APT_Null;
  Hashtbl.replace subjectPublicKeyType_directory rsaEncryption_oid (fun _ -> SPK_RSA);
  ()
