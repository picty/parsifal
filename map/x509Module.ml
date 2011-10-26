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




module DateTimeParser = struct
  type t = datetime_content
  let name = "date_time"
  let params : (string, value) Hashtbl.t = Hashtbl.create 10

  let init () = ()

  let parse _ _ = raise NotImplemented
  let dump _ = raise NotImplemented
  let update _ = raise NotImplemented

  let enrich dt dict =
    Hashtbl.replace dict "year" (V_Int dt.year);
    Hashtbl.replace dict "month" (V_Int dt.month);
    Hashtbl.replace dict "day" (V_Int dt.day);
    Hashtbl.replace dict "hour" (V_Int dt.hour);
    Hashtbl.replace dict "minute" (V_Int dt.minute);
    match dt.second with
      | None -> ()
      | Some sec -> Hashtbl.replace dict "second" (V_Int sec)

  let to_string o = string_of_datetime (Some o)
end

module DateTimeModule = Make (DateTimeParser)
let _ = add_module ((module DateTimeModule : MapModule))




module X509Parser = struct
  type t = certificate
  let name = "x509_ng"
  let params : (string, value) Hashtbl.t = Hashtbl.create 10

  let init () = ()


  let parse name stream =
    let tolerance = eval_as_int (Hashtbl.find Asn1Module.Asn1Parser.params "_tolerance")
    and minDisplay = eval_as_int (Hashtbl.find Asn1Module.Asn1Parser.params "_minDisplay") in
    let ehf = Asn1.Engine.default_error_handling_function tolerance minDisplay in
    let pstate = Asn1.Engine.pstate_of_stream ehf name stream in
    try
      let res = Asn1Constraints.constrained_parse_opt (certificate_constraint object_directory)
	Asn1.Asn1EngineParams.s_specfatallyviolated pstate
      in
      match res with
	| None -> raise (ContentError ("Certificate expected"))
	| Some dn -> dn
    with
      | Asn1.Engine.ParsingError (err, sev, pstate) ->
	raise (ContentError ("Parsing error: " ^ (Asn1.Engine.string_of_exception err sev pstate)))

  let dump cert = raise NotImplemented

  let enrich cert dict =
    let handle_unique_id id_name = function
      | None -> ()
      | Some (n, s) -> Hashtbl.replace  dict id_name (V_BitString (n, s))
    in
    let handle_datetime id_name = function
      | None -> ()
      | Some dt ->
	let datetime_value = DateTimeModule.register dt in
	Hashtbl.replace dict id_name datetime_value
    in

    (* TODO: Add all the missing fields! *)
    begin
      match cert.tbs.version with
	| None -> ()
	| Some v -> Hashtbl.replace dict "version" (V_Int v)
    end;
    Hashtbl.replace dict "serial" (V_Bigint cert.tbs.serial);

    (* sigalgo *)

    let issuer_value = DNModule.register cert.tbs.issuer in
    Hashtbl.replace dict "issuer" issuer_value;

    handle_datetime "not_before" cert.tbs.validity.not_before;
    handle_datetime "not_after" cert.tbs.validity.not_after;

    let subject_value = DNModule.register cert.tbs.subject in
    Hashtbl.replace dict "subject" subject_value;

    (* pk_info *)
    handle_unique_id "issuer_unique_id" cert.tbs.issuer_unique_id;
    handle_unique_id "subject_unique_id" cert.tbs.subject_unique_id;
    (* extensions *)
    (* cert_sig_algo *)
    (* signature *)
    ()

  let update dict = raise NotImplemented

  (* TODO *)
  let to_string cert = string_of_certificate true "" (Some name_directory) cert
end

module X509Module = Make (X509Parser)
let _ = add_module ((module X509Module : MapModule))
