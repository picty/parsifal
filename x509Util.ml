open Common
open Asn1Engine
open ParsingEngine

(* Generic functions for asn1Qualified objects *)

type ('a, 'b, 'c) asn1_directory = {
  qualified_object_name : string;
  object_type_parse_fun : string_input -> 'a;
  get_parser : 'a -> (string_input -> 'b);
  finalizer : 'a -> 'b -> 'c;
}

let parse_asn1_qualified_object_content dir input =
  let _object_type = dir.object_type_parse_fun input in
  let parse_fun = dir.get_parser _object_type in
  let _object_value = parse_fun input in
  dir.finalizer _object_type _object_value

let parse_asn1_qualified_object dir input =
  extract_asn1_object dir.qualified_object_name
    (AH_Simple (C_Universal, true, T_Sequence))
    (parse_asn1_qualified_object_content dir) input



(* AlgorithmIdentifier *)

type algorithmIdentifier = {
  algorithmId : int list;
  algorithmParams : asn1_object option;
}

let finalize_algorithmIdentifier i p = {
  algorithmId = i;
  algorithmParams = p;
}

let algorithmIdentifier_directory = {
  qualified_object_name = "algorithmIdentifier";
  object_type_parse_fun = extract_asn1_object "algorithmId" (AH_Simple (C_Universal, false, T_OId)) (parse_der_oid);
  get_parser = (fun _ -> parse_asn1_object_opt);
  finalizer = finalize_algorithmIdentifier;
}

let parse_algorithmIdentifier_content = parse_asn1_qualified_object_content algorithmIdentifier_directory
let parse_algorithmIdentifier = parse_asn1_qualified_object algorithmIdentifier_directory



(* SubjectPublicKeyInfo *)

type subjectPublicKey_content =
  | RSA of RSAKey.rsa_public_key
  | UnparsedPublicKey of asn1_object

type subjectPublicKeyInfo = {
  algorithm : algorithmIdentifier;
  subjectPublicKey : subjectPublicKey_content;
}

let finalize_subjectPublicKeyInfo a spk = {
  algorithm = a;
  subjectPublicKey = spk;
}

let pki_parsers : (int list, (asn1_object option -> string_input -> subjectPublicKey_content)) Hashtbl.t = Hashtbl.create 10

let default_parser _ input = UnparsedPublicKey (parse_asn1_object input)

let get_pki_parser algo =
  let f = hash_get pki_parsers algo.algorithmId default_parser in
  let pki_parser input =
    let (_nbits, pki_content) = extract_asn1_object "subjectPublicKey_bitstring"
                                (AH_Simple (C_Universal, false, T_BitString))
				(parse_der_bitstring) input
    in
    (* TODO:    if nbits <> 0 then *)
    let new_input = { (input_of_string "subjectPublicKey_content" pki_content)
		      with history = (input.cur_name, input.cur_offset, Some input.cur_length)::input.history }
    in f algo.algorithmParams new_input
  in pki_parser



let subjectPublicKeyInfo_directory = {
  qualified_object_name = "subjectPublicKeyInfo";
  object_type_parse_fun = parse_algorithmIdentifier;
  get_parser = get_pki_parser;
  finalizer = finalize_subjectPublicKeyInfo;
}

let parse_subjectPublicKeyInfo_content = parse_asn1_qualified_object_content subjectPublicKeyInfo_directory
let parse_subjectPublicKeyInfo = parse_asn1_qualified_object subjectPublicKeyInfo_directory



(* register the OId in a general table *)
let rsaEncryption_oid = [42;840;113549;1;1;1]

let _ =
  register_oid rsaEncryption_oid "rsaEncryption";
  Hashtbl.replace pki_parsers rsaEncryption_oid (fun _ input -> RSA (RSAKey.parse_rsa_public_key input))
