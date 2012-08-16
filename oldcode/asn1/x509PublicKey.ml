open Types
open Modules
open Printer
open ParsingEngine
open Asn1
open Asn1Constraints
open X509Misc


(* Public key *)


(* This param is declared here, but is accessible via the x509 module *)
let parse_public_key = ref true

type public_key_info =
(*  | UnparsedPublicKey of oid_object * int * string
  | ParsedPublicKey of value*)
 {
  pk_algo : oid_object;
  public_key : value;
  (* binary_tring if unparsed, DSA/RSA object if parsed *)
  (* if public_key is *not* a binary_string, we should not take pk_algo into account *)
}


let empty_public_key_info = {
  pk_algo = empty_oid_object;
  public_key = V_Unit
}

type pk_parse_fun = asn1_object option -> int -> string -> value
let (pubkey_directory : (int list, pk_parse_fun) Hashtbl.t) = Hashtbl.create 10

let extract_public_key_info = function
  | Some algo, Some (n, pk) ->
    let pk_val =
      try
	if !parse_public_key then begin
	  let extract_aux = Hashtbl.find pubkey_directory algo.oo_id in
	  extract_aux algo.oo_content n pk
	end else V_BitString (n, pk)
      with Not_found -> V_BitString (n, pk)
    in { pk_algo = algo; public_key = pk_val }
  | _ -> empty_public_key_info

let pubkeyalgo_constraint : oid_object asn1_constraint =
  object_constraint PubKeyAlgo s_specfatallyviolated "Public Key Algorithm"

let public_key_info_constraint : public_key_info asn1_constraint =
  custom_pair_cons C_Universal 16 "Public Key Info" extract_public_key_info
    pubkeyalgo_constraint bitstring_cons s_specfatallyviolated


(* TODO: Improve this *)
let string_of_raw_public_key_info pki =
  let strs = [string_of_oid_object (Some "Algorithm") pki.pk_algo; PrinterLib._string_of_value None true pki.public_key] in
  let c, ml = PrinterLib.flatten_strlist strs in
  PrinterLib._string_of_strlist (Some "Public Key Info") (only_ml ml) c

let string_of_public_key_info pki =
  match pki.public_key with
    | V_BitString (n, pk) -> string_of_raw_public_key_info pki
    | v ->
  let strs = [PrinterLib._string_of_value None true v] in
  let c, ml = PrinterLib.flatten_strlist strs in
  PrinterLib._string_of_strlist (Some "Public Key Info") (only_ml ml) c



module PublicKeyInfoParser = struct
  let name = "public_key_info"
  type t = public_key_info
  let params = []

  let parse = constrained_parse public_key_info_constraint

  let dump pki = raise (NotImplemented "public_key_info.dump")

  let enrich pki dict =
    Hashtbl.replace dict "algorithm" (V_String (Asn1.string_of_oid pki.pk_algo.oo_id));
    begin
      match pki.pk_algo.oo_content with
	| None -> ()
	| Some o -> Hashtbl.replace dict "parameters" (Asn1Parser.value_of_asn1_content o.a_content)
    end;
    Hashtbl.replace dict "public_key" pki.public_key

  let update dict = raise (NotImplemented "public_key_info.update")

  let to_string = string_of_public_key_info
  let functions = []
end

module PublicKeyInfoModule = MakeParserModule (PublicKeyInfoParser)
let _ = add_object_module ((module PublicKeyInfoModule : ObjectModule))
