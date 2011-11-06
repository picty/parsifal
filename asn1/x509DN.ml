open Types
open Modules
open ParsingEngine
open Asn1
open Asn1Constraints
open X509Misc


(* Distinguished names *)

type atv = oid_object
type rdn = atv list
type dn = rdn list

let atv_constraint dir : atv asn1_constraint =
  object_constraint dir ATV s_specfatallyviolated "ATV"
let rdn_constraint dir : rdn asn1_constraint =
  setOf_cons Common.identity "Relative DN" (atv_constraint dir) (AtLeast (1, s_specfatallyviolated))
let dn_constraint dir name : dn asn1_constraint =
  seqOf_cons Common.identity name (rdn_constraint dir) AlwaysOK

let string_of_atv indent atv =
  let atv_opts = { type_repr = NoType; data_repr = PrettyData;
		   indent_output = false } in
  indent ^ (string_of_oid atv.oo_id) ^
    (match atv.oo_content with
      | None -> ""
      | Some o ->
	 ": " ^ (string_of_object "" atv_opts o)
    ) ^ "\n"

let string_of_rdn indent rdn =
  String.concat "" (List.map (string_of_atv indent) rdn)

let string_of_dn indent dn =
  String.concat "" (List.map (string_of_rdn indent) dn)



module DNParser = struct
  let name = "dn"
  type t = dn
  let params = []

  let parse = constrained_parse (dn_constraint object_directory name)

  let dump dn = raise NotImplemented

  (* TODO: is it really cool to do that as enrich ? *)
  let enrich dn dict =
    let rec handle_atv = function
      | [] -> ()
      | atv::r ->
	let oid = Asn1.string_of_oid atv.oo_id in
	let value =
	  match atv.oo_content with
	    | None -> V_Unit
	    | Some o -> Asn1Parser.value_of_asn1_content o.a_content
	in
        (* Add code to retain the order of the ATVs, and the asn1 class and tag of the objects -> needed for update *)
	Hashtbl.add dict oid value;
	handle_atv r
    in
    handle_atv (List.flatten dn)

  let update dict = raise NotImplemented

  let to_string dn = string_of_dn "" dn
end

module DNModule = MakeParserModule (DNParser)
let _ = add_module ((module DNModule : Module))

