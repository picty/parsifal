

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


let mk_desc_type (name, fields, _) =
  Printf.printf "type %s = {\n" name;
  let aux (fn, ft, fo, _) =
    Printf.printf "  %s : %s;\n" fn (ocaml_type_of_field_type fo ft)
  in
  List.iter aux fields;
  print_endline "}\n\n"


let mk_parse_fun (name, fields, header_expected) =
  Printf.printf "let parse_%s_content input =\n" name;
  let parse_aux (fn, ft, fo, fh) =
    let indent = if fo then begin
      Printf.printf "  let tmp_offset_before_%s = input.cur_offset in\n" fn;
      Printf.printf "  let _%s = try\n" fn;
      "    "
    end else "  " in
    begin
      match ft, fh with
	| AT_Custom (module_name, type_name), None ->
	  Printf.printf "%slet _%s = %sparse_%s input in\n" indent fn (mk_module_prefix module_name) type_name
	| AT_Anything, None ->
	  Printf.printf "%slet _%s = parse_asn1_object input in\n" indent fn
	| AT_Anything, _ -> failwith "AT_Anything expected header can not be overriden"
	| _ -> 
	  let hdr_constraint = header_constraint fh ft
	  and parse_name, parse_fun = parse_fun_of_field_type fn ft in
	  Printf.printf "%slet _%s = extract_asn1_object \"%s\" (%s) (%s) input in\n"
	    indent fn (quote_string parse_name) hdr_constraint parse_fun
    end;
    if fo then begin
      Printf.printf "    Some _%s\n" fn;
      Printf.printf "  with (Asn1Exception _) ->\n";
      Printf.printf "    input.cur_offset <- tmp_offset_before_%s;\n" fn;
      Printf.printf "    None\n";
      Printf.printf "  in\n";
    end
  in
  let mkrec_aux (fn, ft, _, fh) = Printf.printf "    %s = _%s;\n" fn fn in
  List.iter parse_aux fields;
  print_endline "  {";
  List.iter mkrec_aux fields;
  print_endline "  }\n\n";

  Printf.printf "let parse_%s input =\n" name;
  let hdr_constraint = external_header_constraint header_expected in
  Printf.printf "  extract_asn1_object \"%s\" (%s) (parse_%s_content) input\n\n"
    (quote_string name) hdr_constraint name


let handle_desc (desc : description) =
  mk_desc_type desc;
  mk_parse_fun desc;
  print_newline ()


let _ =
  print_endline "open Asn1Enums";
  print_endline "open ParsingEngine";
  print_endline "open Asn1Engine\n";
  List.iter handle_desc descriptions

