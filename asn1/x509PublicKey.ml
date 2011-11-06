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

type public_key_info = {
  pk_algo : oid_object;
  public_key : value;
  (* string if unparsed, DSA/RSA object if parsed *)
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
let string_of_public_key_info indent pki =
  let mk_content new_indent qs pki =
    [string_of_oid_object new_indent pki.pk_algo;
     PrinterLib._string_of_value new_indent qs pki.public_key]
  in
  PrinterLib._string_of_constructed "Public Key Info:" "" indent mk_content pki



module PublicKeyInfoParser = struct
  let name = "public_key_info"
  type t = public_key_info
  let params = []

  let parse = constrained_parse public_key_info_constraint

  let dump pki = raise NotImplemented
  let enrich pki dict = raise NotImplemented
  let update dict = raise NotImplemented

  let to_string = string_of_public_key_info
end

module PublicKeyInfoModule = MakeParserModule (PublicKeyInfoParser)
let _ = add_module ((module PublicKeyInfoModule : Module))
