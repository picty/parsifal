let int_size = function
  | IT_UInt8 -> 8
  | IT_UInt16 -> 16
  | IT_UInt24 -> 24
  | IT_UInt32 -> 32

let rec ocaml_type_of_field_type = function
  | FT_Char -> "char"
  | FT_Integer _ -> "int"
  | FT_Enum (_, module_name, type_name) -> module_name ^ "." ^ type_name
  | FT_IPv4 | FT_IPv6 -> "string"
  | FT_String _ -> "string"
  | FT_List (_, subtype) ->
    "(" ^ (ocaml_type_of_field_type subtype) ^ ") list"
  | FT_Custom t -> t

let ocaml_type_of_field_type_and_options t optional =
  let type_string = ocaml_type_of_field_type t in
  if optional
  then Printf.sprintf "(%s) option" type_string
  else type_string

let rec parse_fun_of_field_type name = function
  | FT_Char -> "parse_char"
  | FT_Integer it ->
    Printf.sprintf "parse_uint%d" (int_size it)

  | FT_Enum (int_type, module_name, type_name) ->
    Printf.sprintf "(fun input -> %s.%s_of_int (parse_uint%d input))" module_name type_name (int_size int_type)

  | FT_IPv4 -> "parse_string 4"
  | FT_IPv6 -> "parse_string 16"
  | FT_String (FixedLen n) -> "parse_string " ^ (string_of_int n)
  | FT_String (VarLen int_t) ->
    Printf.sprintf "parse_varlen_string \"%s\" parse_uint%d" name (int_size int_t)
  | FT_String (Remaining) -> "parse_rem_string"

  | FT_List (FixedLen n, subtype) ->
    Printf.sprintf "parse_list %d (%s)" n (parse_fun_of_field_type name subtype)
  | FT_List (VarLen int_t, subtype) ->
    Printf.sprintf "parse_varlen_list \"%s\" parse_uint%d (%s)" name (int_size int_t) (ocaml_type_of_field_type subtype)
  | FT_List (Remaining, subtype) ->
    Printf.sprintf "parse_rem_list (%s)" (parse_fun_of_field_type name subtype)

  | FT_Custom t -> "parse_" ^ t

let rec dump_fun_of_field_type = function
  | FT_Char -> "dump_char"
  | FT_Integer it -> Printf.sprintf "dump_uint%d" (int_size it)

  | FT_Enum (int_type, module_name, type_name) ->
    Printf.sprintf "(fun v -> dump_uint%d (%s.int_of_%s v))" (int_size int_type) module_name type_name

  | FT_String (VarLen int_t) ->
    Printf.sprintf "dump_varlen_string dump_uint%d" (int_size int_t)
  | FT_IPv4
  | FT_IPv6
  | FT_String _ -> "dump_string"

  | FT_List (VarLen int_t, subtype) ->
    Printf.sprintf "dump_varlen_list dump_uint%d (%s)" (int_size int_t) (dump_fun_of_field_type subtype)
  | FT_List (_, subtype) ->
    Printf.sprintf "dump_list (%s)" (dump_fun_of_field_type subtype)

  | FT_Custom t -> "dump_" ^ t


let mk_desc_type (name, fields) =
  Printf.printf "type %s = {\n" name;
  let aux (fn, ft, fo) =
    Printf.printf "  %s : %s;\n" fn (ocaml_type_of_field_type_and_options ft fo)
  in
  List.iter aux fields;
  print_endline "}\n\n"


let mk_parse_fun (name, fields) =
  Printf.printf "let parse_%s input =\n" name;
  let parse_aux (fn, ft, fo) =
    if fo
    then begin
      Printf.printf "  let _%s = if eos input then None\n" fn;
      Printf.printf "            else Some (%s input) in\n" (parse_fun_of_field_type name ft)
    end
    else Printf.printf "  let _%s = %s input in\n" fn (parse_fun_of_field_type name ft)
  in
  let mkrec_aux (fn, _, _) = Printf.printf "    %s = _%s;\n" fn fn in
  List.iter parse_aux fields;
  print_endline "  {";
  List.iter mkrec_aux fields;
  print_endline "  }\n"


let mk_dump_fun (name, fields) =
  Printf.printf "let dump_%s %s =\n" name name;
  let dump_aux (fn, ft, fo) =
    if fo
    then begin
      (Printf.sprintf "  begin\n") ^
      (Printf.sprintf "    match %s.%s with\n" name fn) ^
      (Printf.sprintf "      | None -> ()\n") ^
      (Printf.sprintf "      | Some x -> %s x\n" (dump_fun_of_field_type ft)) ^
      (Printf.sprintf "  end\n")
    end
    else Printf.sprintf "  %s %s.%s" (dump_fun_of_field_type ft) name fn
  in
  print_endline (String.concat " ^ \n" (List.map dump_aux fields));
  print_endline "\n"


let handle_desc (desc : description) =
  print_endline "open ParsingEngine";
  print_endline "open DumpingEngine\n";
  mk_desc_type desc;
  mk_parse_fun desc;
  mk_dump_fun desc;
  print_newline ()


let _ =
  List.iter handle_desc descriptions
