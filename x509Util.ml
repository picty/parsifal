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
type subjectPublicKey =
  | RSA of RSAKey.rsa_public_key
  | UnparsedPublicKey of der_object

let pki_parsers : (int list, (algorithmParams option -> string_input -> subjectPublicKey)) Hashtbl.t = Hashtbl.create 10

let parse_subjectPublicKey algo input =
  let default_parser _ input = UnparsedPublicKey (parse_der_object input) in
  let f = hash_get pki_parsers algo.algorithmId default_parser in
  let (_nbits, pki_content) = parse_der_bitstring input in
  (* TODO:    if nbits <> 0 then *)
  let new_input = { (input_of_string "subjectPublicKey_content" pki_content)
                    with history = (input.cur_name, input.cur_offset, Some input.cur_length)::input.history }
  in f algo.algorithmParams new_input

let dump_subjectPublicKey _ = raise (ParsingException (NotImplemented "dump_subjectPublicKey", []))
let print_subjectPublicKey ?indent:(indent="") ?name:(name="subjectPublicKey") = function
  | RSA k -> RSAKey.print_rsa_public_key ~indent:indent ~name:name k
  | UnparsedPublicKey o -> print_der_object ~indent:indent ~name:name o

struct subjectPublicKeyInfo_content = {
  algorithm : algorithmIdentifier;
  subjectPublicKey : subjectPublicKey(algorithm)
}
asn1_alias subjectPublicKeyInfo




(* register the OId in a general table *)
let rsaEncryption_oid = [42;840;113549;1;1;1]

let _ =
  register_oid rsaEncryption_oid "rsaEncryption";
  Hashtbl.replace algorithmParamsType_directory rsaEncryption_oid APT_Null;
  Hashtbl.replace pki_parsers rsaEncryption_oid (fun _ input -> RSA (RSAKey.parse_rsa_public_key input))
