type expected_header_string = string option

type field_type =
  | AT_Boolean
  | AT_SmallInteger
  | AT_Integer
  | AT_BitString
  (*  TODO: AT_EnumeratedBitString *)
  | AT_Null
  | AT_OId
  (* AT_String (constraints : None -> no_constraint, Some s -> $s_constraint) *)
  | AT_String of string option
  | AT_Primitive
  | AT_Container of expected_header_string * field_type
  (* AT_SequenceOf (name of the sequence [default is proposed_name_list], min, max, sub_type, sub_header) *)
  | AT_SequenceOf of string option * int option * int option * expected_header_string * field_type
  | AT_SetOf of string option * int option * int option * expected_header_string * field_type

  | AT_Custom of string option * string
  | AT_Anything

type asn1_option =
  | AO_EnrichRawString
  | AO_EnrichASN1Info
  | AO_TopLevel

(* TODO: Add constraints
    - optional fields SHOULDs and SHOULDNOTs *)


type field_desc = {
  field_name : string;
  field_type : field_type;
  field_optional : bool;
  field_expected_header : string option;
}

type description = {
  name : string;
  fields : field_desc list;
  expected_header : string option;
  options : asn1_option list;
}


let mkf ?opt:(o=false) ?hdr:(h=None) n t = {
  field_name = n;
  field_type = t;
  field_optional = o;
  field_expected_header = h;
}


(* Generic functions *)

let mk_module_prefix = function
  | None -> ""
  | Some module_name -> module_name ^ "."

let default_header = function
  | AT_Boolean -> "AH_Simple (C_Universal, false, T_Boolean)"
  | AT_SmallInteger
  | AT_Integer -> "AH_Simple (C_Universal, false, T_Integer)"
  | AT_BitString -> "AH_Simple (C_Universal, false, T_BitString)"
  | AT_Null -> "AH_Simple (C_Universal, false, T_Null)"
  | AT_OId -> "AH_Simple (C_Universal, false, T_OId)"
  | AT_Container _ | AT_SequenceOf _ | AT_Custom _ ->
    "AH_Simple (C_Universal, true, T_Sequence)"
  | AT_SetOf _ ->
    "AH_Simple (C_Universal, true, T_Set)"
  | AT_String _ | AT_Primitive | AT_Anything ->
    failwith "No default header there"

let header_constraint header_expected field_type =
  match header_expected, field_type with
    | Some s, _ -> s
    | None, t -> default_header t

let external_header_constraint = function
  | None -> "AH_Simple (C_Universal, true, T_Sequence)"
  | Some s -> s



let rec _ocaml_type_of_field_type = function
  | AT_Boolean -> "bool"
  | AT_SmallInteger -> "int"
  | AT_Integer -> "string"
  | AT_BitString -> "int * string"
  | AT_Null -> "unit"
  | AT_OId -> "int list"
  | AT_String _ -> "string"
  | AT_Primitive -> "string"
  | AT_Container (_, sub_type) -> _ocaml_type_of_field_type sub_type
  | AT_SequenceOf (_, _, _, _, sub_type)
  | AT_SetOf (_, _, _, _, sub_type) -> (_ocaml_type_of_field_type sub_type) ^ " list"
  | AT_Custom (module_name, type_name) -> (mk_module_prefix module_name) ^ type_name
  | AT_Anything -> "asn1_object"

let ocaml_type_of_field_type fo ft =
  let type_string = _ocaml_type_of_field_type ft in
  if fo
  then "(" ^ type_string ^ ") option"
  else type_string

let tr_bound = function
  | None -> "None"
  | Some i -> Printf.sprintf "(Some %d)" i

let rec parse_fun_of_field_type fn = function
  | AT_Boolean -> fn, "parse_der_boolean"
  | AT_SmallInteger -> fn, "parse_der_smallint"
  | AT_Integer -> fn, "parse_der_int"
  | AT_BitString -> fn, "parse_der_bitstring"
  | AT_Null -> fn, "parse_der_null"
  | AT_OId -> fn, "parse_der_oid"
  | AT_String None -> fn, "parse_der_octetstring no_constraint"
  | AT_String (Some cs) -> fn, "parse_der_octetstring " ^ cs ^ "_constraint"
  | AT_Primitive -> fn, "parse_string"

  | AT_Container (exp_h, subtype) ->
    let hdr_constraint = header_constraint exp_h subtype
    and real_name, sub_fun = parse_fun_of_field_type fn subtype in
    let res_name = real_name ^ "_cont"
    and res_fun = Printf.sprintf "extract_asn1_object \"%s\" (%s) (%s)\n\n"
      (quote_string real_name) hdr_constraint sub_fun in
    res_name, res_fun

  | AT_SequenceOf (name, min, max, exp_h, subtype)
  | AT_SetOf (name, min, max, exp_h, subtype) ->
    let hdr_constraint = header_constraint exp_h subtype
    and real_name, sub_fun = parse_fun_of_field_type fn subtype in
    let res_name = pop_opt (real_name ^ "_list") name
    and res_fun = Printf.sprintf "parse_der_list \"%s\" (%s) %s %s (%s)" (quote_string real_name)
      hdr_constraint (tr_bound min) (tr_bound max) sub_fun in 
    res_name, res_fun

  | AT_Custom (module_name, type_name) -> fn, (mk_module_prefix module_name) ^ "parse_" ^ type_name ^ "_content"
  | AT_Anything -> fn, "parse_asn1_object"


let mk_desc_type d =
  Printf.printf "type %s = {\n" d.name;
  let aux field_descr =
    Printf.printf "  %s : %s;\n" field_descr.field_name (ocaml_type_of_field_type field_descr.field_optional field_descr.field_type)
  in
  List.iter aux d.fields;
  if List.mem AO_EnrichASN1Info d.options
  then Printf.printf "  _asn1_info_%s : asn1_info option;\n" d.name;
  if List.mem AO_EnrichRawString d.options
  then Printf.printf "  _raw_%s : string option;\n" d.name;
  print_endline "}\n\n"


let mk_parse_fun d =
  Printf.printf "let parse_%s_content input =\n" d.name;
  let parse_aux fd =
    let indent = if fd.field_optional then begin
      Printf.printf "  let tmp_offset_before_%s = input.cur_offset in\n" fd.field_name;
      Printf.printf "  let _%s = try\n" fd.field_name;
      "    "
    end else "  " in
    begin
      match fd.field_type, fd.field_expected_header with
	| AT_Custom (module_name, type_name), None ->
	  Printf.printf "%slet _%s = %sparse_%s input in\n" indent fd.field_name (mk_module_prefix module_name) type_name
	| AT_Anything, None ->
	  Printf.printf "%slet _%s = parse_asn1_object input in\n" indent fd.field_name
	| AT_Anything, _ -> failwith "AT_Anything expected header can not be overriden"
	| _ -> 
	  let hdr_constraint = header_constraint fd.field_expected_header fd.field_type
	  and parse_name, parse_fun = parse_fun_of_field_type fd.field_name fd.field_type in
	  Printf.printf "%slet _%s = extract_asn1_object \"%s\" (%s) (%s) input in\n"
	    indent fd.field_name (quote_string parse_name) hdr_constraint parse_fun
    end;
    if fd.field_optional then begin
      Printf.printf "    Some _%s\n" fd.field_name;
      Printf.printf "  with (Asn1Exception _) ->\n";
      Printf.printf "    input.cur_offset <- tmp_offset_before_%s;\n" fd.field_name;
      Printf.printf "    None\n";
      Printf.printf "  in\n";
    end
  in
  let mkrec_aux fd = Printf.printf "    %s = _%s;\n" fd.field_name fd.field_name in
  List.iter parse_aux d.fields;
  print_endline "  {";
  List.iter mkrec_aux d.fields;
  let enrich_asn1_info = List.mem AO_EnrichASN1Info d.options
  and enrich_raw_string = List.mem AO_EnrichRawString d.options in
  if enrich_asn1_info
  then Printf.printf "    _asn1_info_%s = None;\n" d.name;
  if enrich_raw_string
  then Printf.printf "    _raw_%s = None;\n" d.name;
  print_endline "  }\n\n";

  Printf.printf "let parse_%s input =\n" d.name;
  let hdr_constraint = external_header_constraint d.expected_header in
  if enrich_asn1_info || enrich_raw_string then begin
    Printf.printf "  let res, asn1_info, raw_string = _extract_asn1_object \"%s\" (%s) (parse_%s_content) input in\n"
      (quote_string d.name) hdr_constraint d.name;
    Printf.printf "  { res with\n";
    if enrich_asn1_info then Printf.printf  "    _asn1_info_%s = Some asn1_info;\n" d.name;
    if enrich_raw_string then Printf.printf "    _raw_%s = Some (raw_string ());\n" d.name;
    Printf.printf "  }\n\n";
  end else begin
    Printf.printf "  extract_asn1_object \"%s\" (%s) (parse_%s_content) input\n\n"
      (quote_string d.name) hdr_constraint d.name
  end;

  if List.mem AO_TopLevel d.options then begin
    Printf.printf "let exact_parse_%s input =\n" d.name;
    Printf.printf "  let res = parse_%s input in\n" d.name;
    Printf.printf "  check_empty_input true input;\n";
    Printf.printf "  res\n\n";

    Printf.printf "let lwt_parse_%s input =\n" d.name;
    if enrich_asn1_info || enrich_raw_string then begin
      Printf.printf "   _lwt_extract_asn1_object \"%s\" (%s) (parse_%s_content) input >>= fun (res, asn1_info, raw_string) ->\n"
	(quote_string d.name) hdr_constraint d.name;
      Printf.printf "  return { res with\n";
      if enrich_asn1_info then Printf.printf  "    _asn1_info_%s = Some asn1_info;\n" d.name;
      if enrich_raw_string then Printf.printf "    _raw_%s = Some (raw_string ());\n" d.name;
      Printf.printf "  }\n\n";
    end else begin
      Printf.printf "  lwt_extract_asn1_object \"%s\" (%s) (parse_%s_content) input\n\n"
	(quote_string d.name) hdr_constraint d.name
    end;
  end


let handle_desc ?options:(o=[]) ?hdr:(h=None) n f =
  let desc = {
    name = n;
    fields = f;
    expected_header = h;
    options = o;
  } in
  mk_desc_type desc;
  mk_parse_fun desc;
  print_newline ()


let _ =
  print_endline "open Lwt";
  print_endline "open Asn1Enums";
  print_endline "open ParsingEngine";
  print_endline "open Asn1Engine\n";;



(* Real information about ASN.1 structures goes after here. *)

