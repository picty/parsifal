open MapEval
open MapModule
open X509
open X509Directory

module DNParser = struct
  type t = dn
  let name = "distinguished_name"
  let params : (string, value) Hashtbl.t = Hashtbl.create 10

  let init () =
    (* TODO: Should that be elsewhere? *)
    Hashtbl.replace params "_resolve_names" (V_Bool true)

  let get_name_resolver () =
    if (eval_as_bool (Hashtbl.find params "_resolve_names"))
    then Some name_directory
    else None


  let parse name stream =
    let tolerance = eval_as_int (Hashtbl.find Asn1Module.Asn1Parser.params "_tolerance")
    and minDisplay = eval_as_int (Hashtbl.find Asn1Module.Asn1Parser.params "_minDisplay") in
    let ehf = Asn1.Engine.default_error_handling_function tolerance minDisplay in
    let pstate = Asn1.Engine.pstate_of_stream ehf name stream in
    try
      let res = Asn1Constraints.constrained_parse_opt (dn_constraint object_directory name)
	Asn1.Asn1EngineParams.s_specfatallyviolated pstate
      in
      match res with
	| None -> raise (ContentError ("Distinguished name expected"))
	| Some dn -> dn
    with
      | Asn1.Engine.ParsingError (err, sev, pstate) ->
	raise (ContentError ("Parsing error: " ^ (Asn1.Engine.string_of_exception err sev pstate)))

  let dump dn = raise NotImplemented

  let enrich dn dict =
    let rec handle_atv = function
      | [] -> ()
      | atv::r ->
	let oid = Asn1.string_of_oid (get_name_resolver ()) atv.oo_id in
	let value =
	  match atv.oo_content with
	    | None -> V_Unit
	    | Some o -> Asn1Module.value_of_asn1_content o
	in
        (* Add code to retain the order of the ATVs, and the asn1 class and tag of the objects -> needed for update *)
	Hashtbl.add dict oid value;
	handle_atv r
    in
    handle_atv (List.flatten dn)

  let update dict = raise NotImplemented

  let to_string dn = string_of_dn "" (get_name_resolver ()) dn
end

module DNModule = Make (DNParser)
let _ = add_module ((module DNModule : MapModule))




