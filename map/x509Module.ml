open MapEval
open MapModule
open X509;;
open X509Directory

module DNParser = struct
  type t = dn
  let name = "distinguished_name"
  let params : (string, value) Hashtbl.t = Hashtbl.create 10

  let init () =
    Hashtbl.replace params "_resolve_names" (V_Bool true);
    Hashtbl.replace params "_tolerance" (V_Int Asn1.Asn1EngineParams.s_specfatallyviolated);
    Hashtbl.replace params "_minDisplay" (V_Int 0)

  let get_name_resolver () =
    if (eval_as_bool (Hashtbl.find params "_resolve_names"))
    then Some name_directory
    else None


  let parse name stream =
    let tolerance = eval_as_int (Hashtbl.find params "_tolerance")
    and minDisplay = eval_as_int (Hashtbl.find params "_minDisplay") in
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
         (* TODO: Factor this shit in a asn1Module *)
	  match atv.oo_content with
	    | None
	    | Some ({Asn1.a_content = Asn1.Null}) -> V_Unit
	    | Some ({Asn1.a_content = Asn1.Boolean b}) -> V_Bool b
	    | Some ({Asn1.a_content = Asn1.Integer i}) -> V_Bigint i
	    | Some ({Asn1.a_content = Asn1.BitString (n, s)}) -> V_BitString (n, s)
	    | Some ({Asn1.a_content = Asn1.OId _}) ->
	      raise NotImplemented (* TODO: Find a suitable solution to be able to update *)
	    | Some ({Asn1.a_content = Asn1.String (s, true)}) -> V_BinaryString s
	    | Some ({Asn1.a_content = Asn1.String (s, false)}) -> V_String s
	    | Some ({Asn1.a_content = Asn1.Constructed _}) ->
	      raise NotImplemented (* Call List.map on asn1Module.make ? *)
	in
        (* Add code to retain the order of the ATVs, and the asn1 class and tag of the objects -> needed for update *)
	Hashtbl.add dict oid value;
	handle_atv r
    in
    handle_atv (List.flatten dn)

  let update dict = raise NotImplemented
(*    { AnswerDump.ip = Common.ip_of_string (enricher.of_string (Hashtbl.find dict "ip"));
      AnswerDump.port = enricher.of_int (Hashtbl.find dict "port");
      AnswerDump.name = enricher.of_string (Hashtbl.find dict "name");
      AnswerDump.client_hello_type = enricher.of_int (Hashtbl.find dict "client_hello_type");
      AnswerDump.msg_type = enricher.of_int (Hashtbl.find dict "msg_type");
      AnswerDump.content = enricher.of_binary_string (Hashtbl.find dict "content"); } *)

  let to_string dn = string_of_dn "" (get_name_resolver ()) dn
end

let _ =
  add_module ((module (Make (DNParser)) : MapModule))
