let rec ocaml_type_of_field_type = function
  | AT_Boolean -> "bool"
  | AT_Integer -> "string"
  | AT_Null -> "unit"
  | AT_OId -> "int list"
  | AT_Primitive -> "string"
  | AT_Custom t -> t

let rec parse_fun_of_field_type = function
  | AT_Boolean -> "parse_der_bool"
  | AT_Integer -> "parse_der_int"
  | AT_Null -> "parse_der_null"
  | AT_OId -> "parse_der_oid"
  | AT_Primitive -> "parse_string"
  | AT_Custom t -> "parse_" ^ t ^ "_content"


let default_header = function
  | AT_Boolean -> "AH_Simple (C_Universal, false, T_Boolean)"
  | AT_Integer -> "AH_Simple (C_Universal, false, T_Integer)"
  | AT_Null -> "AH_Simple (C_Universal, false, T_Null)"
  | AT_OId -> "AH_Simple (C_Universal, false, T_OId)"
  | AT_Primitive | AT_Custom _ -> failwith "No default header there"

let header_constraint header_expected field_type =
  match header_expected, field_type with
    | Some s, _ -> s
    | None, t -> default_header t

let external_header_constraint = function
  | None -> "AH_Simple (C_Universal, true, T_Sequence)"
  | Some s -> s

let mk_desc_type (name, fields, _) =
  Printf.printf "type %s = {\n" name;
  let aux (fn, ft, _) =
    Printf.printf "  %s : %s;\n" fn (ocaml_type_of_field_type ft)
  in
  List.iter aux fields;
  print_endline "}\n\n"


let mk_parse_fun (name, fields, header_expected) =
  Printf.printf "let parse_%s_content input =\n" name;
  let parse_aux (fn, ft, fh) =
    match ft, fh with
      | AT_Custom t, None ->
	Printf.printf "  let _%s = parse_%s input in\n" fn t
      | _ -> 
	let hdr_constraint = header_constraint fh ft
	and parse_fun = parse_fun_of_field_type ft in
	Printf.printf "  let _%s = extract_asn1_object input \"%s\" (%s) (%s) in\n" fn fn hdr_constraint parse_fun
  in
  let mkrec_aux (fn, ft, fh) = Printf.printf "    %s = _%s;\n" fn fn in
  List.iter parse_aux fields;
  print_endline "  {";
  List.iter mkrec_aux fields;
  print_endline "  }\n\n";

  Printf.printf "let parse_%s input =\n" name;
  let hdr_constraint = external_header_constraint header_expected in
  Printf.printf "  extract_asn1_object input \"%s\" (%s) (parse_%s_content)\n\n" name hdr_constraint name


let handle_desc (desc : description) =
  print_endline "open Asn1Enums";
  print_endline "open ParsingEngine";
  print_endline "open Asn1Engine\n";
  mk_desc_type desc;
  mk_parse_fun desc;
  print_newline ()


let _ =
  List.iter handle_desc descriptions

