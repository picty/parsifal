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

let populate_atv_directory (id, name, short, value) =
  register_oid ~short:short id name;
  Hashtbl.replace attributeValueType_directory id value

union attributeValue [enrich] (UnparsedAV of der_object) =
  | AVT_IA5String len_cons -> AV_IA5String of der_ia5string (len_cons)
  | AVT_PrintableString len_cons -> AV_PrintableString of der_printablestring (len_cons)
  | AVT_DirectoryString len_cons -> AV_DirectoryString of directoryString (len_cons)

(* Sordid hack. TODO: auto-generate that with an option laxist? *)
let parse_attributeValue t input =
  match try_parse (parse_attributeValue t) input with
  | None -> parse_attributeValue AVT_Anything input
  | Some res -> res

struct atv_content = {
  attributeType : der_oid;
  attributeValue : attributeValue(hash_get attributeValueType_directory attributeType AVT_Anything)
}
asn1_alias atv

(* TODO: Rewrite this once to_string is generated automatically, at least for scalar types? *)
let string_of_atv_value = function
  | UnparsedAV { a_content = String (s, false) }
  | AV_DirectoryString (UnparsedDirectoryString { a_content = String (s, false) })
  | AV_PrintableString s
  | AV_DirectoryString (DS_T61String s|DS_PrintableString s|
      DS_UniversalString s|DS_UTF8String s|DS_BMPString s)
  | AV_IA5String s -> s  (* TODO: Was a quote_string here... *)
  | UnparsedAV { a_content = String (s, true) } -> hexdump s

  | AV_DirectoryString (UnparsedDirectoryString _)
  | UnparsedAV { a_content = UnparsedDER _ } -> "[Unparsed]"
  | UnparsedAV _ -> "NON-STRING-VALUE"

let string_of_atv atv =
  "/" ^ (short_string_of_oid atv.attributeType) ^ "=" ^ (string_of_atv_value atv.attributeValue)

(* TODO: Add constraints on set of [min, max] *)
asn1_alias rdn = set_of atv  (* min = 1 *)
asn1_alias distinguishedName = seq_of rdn

let string_of_distinguishedName dn =
  String.concat "" (List.map string_of_atv (List.flatten dn))

let value_of_distinguishedName dn =
  let update h k v =
    try Hashtbl.replace h k (v::(Hashtbl.find h k))
    with Not_found -> Hashtbl.replace h k [v]
  in
  let add_atv h atv =
    let oid = atv.attributeType
    and v = VString (string_of_atv_value atv.attributeValue, false) in
    let n1 = short_string_of_oid oid
    and n2 = raw_string_of_oid oid in
    update h n1 v;
    if n1 <> n2 then update h n2 v
  in
  let mk_shortcut n vs accu = match vs with
    | v::_ -> ("@all_" ^ n, VList vs)::("@" ^ n, v )::accu
    | [] -> ("@all_" ^ n, VUnit)::accu
  in
  let h = Hashtbl.create 10 in
  List.iter (add_atv h) (List.flatten dn);

  let shortcuts = Hashtbl.fold mk_shortcut h []
  and string_of_entry = "@string_of", VString (string_of_distinguishedName dn, false)
  and raw_content_entry = "raw_content", VList (List.map value_of_rdn dn) in
  VRecord (string_of_entry::raw_content_entry::shortcuts)


(***********************)
(* AlgorithmIdentifier *)
(***********************)

type algorithmParamsType =
  | APT_Null
  | APT_DSAParams
  | APT_Unknown

let algorithmParamsType_directory : (int list, algorithmParamsType) Hashtbl.t = Hashtbl.create 10

let populate_alg_directory dir (id, name, algParam, value) =
  register_oid id name;
  Hashtbl.replace algorithmParamsType_directory id algParam;
  Hashtbl.replace dir id value


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

union signature [enrich] (UnparsedSignature of binstring) =
  | ST_DSA -> DSASignature of DSAKey.dsa_signature
  | ST_RSA -> RSASignature of RSAKey.rsa_signature



(************)
(* Validity *)
(************)

(* TODO: this "exhaustive" should produce a warning *)
asn1_union der_time [enrich; exhaustive] (UnparsedTime) =
  | (C_Universal, false, T_UTCTime) -> UTCTime of der_utc_time_content
  | (C_Universal, false, T_GeneralizedTime) -> GeneralizedTime of der_generalized_time_content

struct validity_content = {
  notBefore : der_time;
  notAfter : der_time
}
asn1_alias validity
