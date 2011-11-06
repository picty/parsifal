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

let atv_constraint : atv asn1_constraint =
  object_constraint ATV s_specfatallyviolated "ATV"
let rdn_constraint : rdn asn1_constraint =
  setOf_cons Common.identity "Relative DN" atv_constraint (AtLeast (1, s_specfatallyviolated))
let dn_constraint name : dn asn1_constraint =
  seqOf_cons Common.identity name rdn_constraint AlwaysOK

let string_of_atv indent _ atv =
  let id = string_of_oid atv.oo_id in
  let c = match atv.oo_content with
    | None -> []
    | Some o -> string_of_content indent o.a_content
  in
  String.concat ": " (id::c)

let string_of_rdn indent qs rdn =
  String.concat ", " (List.map (string_of_atv indent qs) rdn)

let string_of_dn title indent dn =
  let aux i qs = List.map (string_of_rdn i qs) in
  Printer.PrinterLib._string_of_constructed title "" indent aux dn



module DNParser = struct
  let name = "dn"
  type t = dn
  let params = []

  let parse = constrained_parse (dn_constraint name)

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

  let to_string = string_of_dn "Distinguished Name"
end

module DNModule = MakeParserModule (DNParser)
let _ = add_module ((module DNModule : Module))




(* ATVs directory entries *)

let (initial_directory : (int list, string) Hashtbl.t) = Hashtbl.create 20

let add_atv oid name initial cons sev =
  Hashtbl.add name_directory oid name;
  match initial with
    | None -> ()
    | Some s -> Hashtbl.add initial_directory oid s;
  Hashtbl.add object_directory (ATV, oid) (cons, sev)


let add_standard_atv () =
  add_atv [85;4;41] "name" None directory_name_cons s_benign;
  add_atv [85;4;4] "surname" None directory_name_cons s_benign;
  add_atv [85;4;42] "givenName" None directory_name_cons s_benign;
  add_atv [85;4;43] "initials" None directory_name_cons s_benign;
  add_atv [85;4;44] "genrationQualifier" None directory_name_cons s_benign;
  add_atv [85;4;3] "commonName" (Some "CN") directory_name_cons s_benign;
  add_atv [85;4;7] "locality" (Some "L") directory_name_cons s_benign;
  add_atv [85;4;8] "state" (Some "S") directory_name_cons s_benign;
  add_atv [85;4;10] "organization" (Some "O") directory_name_cons s_benign;
  add_atv [85;4;11] "organizationalUnit" (Some "OU") directory_name_cons s_benign;
  add_atv [85;4;12] "title" None directory_name_cons s_benign;
  add_atv [85;4;46] "dnQualifier" None printablestring_cons s_benign;
  (* TODO: Add constraint on length ? *)
  add_atv [85;4;6] "country" (Some "C") printablestring_cons s_benign;
  add_atv [85;4;5] "serial" None printablestring_cons s_benign;
  add_atv [85;4;65] "pseudonym" None directory_name_cons s_benign;
  add_atv [9;2342;19200300;100;1;25] "domainComponent" None ia5string_cons s_benign;
  add_atv [42;840;113549;1;9;1] "emailAddress" None ia5string_cons s_benign;;



let _ =
  add_standard_atv ();;
