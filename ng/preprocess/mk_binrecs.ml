(* BINARY RECORDS *)

let do_lwt = true


(* Simple records (a.k.a structs) *)

type integer_type =
  | IT_UInt8
  | IT_UInt16
  | IT_UInt24
  | IT_UInt32

type field_name = string

type field_len =
  | FixedLen of int
  | VarLen of integer_type
  | Remaining

type field_type =
  | FT_Empty
  | FT_Char
  | FT_Integer of integer_type
  | FT_Enum of string * string
  | FT_IPv4
  | FT_IPv6
  | FT_String of field_len * bool
  | FT_List of field_len * field_type
  | FT_Container of integer_type * field_type
  | FT_Custom of (string option) * string * (string list)

(* TODO: Add options for lists (AtLeast, AtMost) and for options *)

type field_desc = field_name * field_type * bool

type record_option =
  | RO_AddParseParameter of string
  | RO_NoContextParameter

type record_description = string * field_desc list * record_option list




(* Choices (a.k.a unions) *)

type discriminator_type =
  | Explicit of string  (* the discriminator will be given as an arg *)
  | Implicit of string  (* the discriminator comes from the context *)
(* If the discriminator is Implict x
   - context is None -> Unparsed
   - context is Some context -> the discriminator is context, whatever this means (generally "context.field") *)

(* Discrimating value, Constructor name, Constructor subtype (module + type name) *)
type choice_desc = string * string * field_type

type choice_option =
  | CO_EnrichByDefault
  | CO_ExhaustiveDiscriminatingVals
  | CO_AddParseParameter of string
  | CO_NoContextParameter

(* Type name, Module containing the discriminating values, Discriminator, Choice list, Constructor if unparsed, Default value of the enrich ref *)
type choice_description = string * string option * discriminator_type * choice_desc list * string * choice_option list



type what = All | OnlyTypes | OnlyFuns



(* Generic functions *)

let mk_module_prefix = function
  | None -> ""
  | Some module_name -> module_name ^ "."



(* Records functions *)

let int_size = function
  | IT_UInt8 -> 8
  | IT_UInt16 -> 16
  | IT_UInt24 -> 24
  | IT_UInt32 -> 32

let rec ocaml_type_of_field_type = function
  | FT_Empty -> failwith "Unexpected type in ocaml_type_of_field_type: empty"
  | FT_Char -> "char"
  | FT_Integer _ -> "int"
  | FT_Enum (module_name, type_name) -> module_name ^ "." ^ type_name
  | FT_IPv4 | FT_IPv6 -> "string"
  | FT_String _ -> "string"
  | FT_List (_, subtype) ->
    "(" ^ (ocaml_type_of_field_type subtype) ^ ") list"
  | FT_Container (_, subtype) -> ocaml_type_of_field_type subtype
  | FT_Custom (module_name, type_name, _) -> (mk_module_prefix module_name) ^ type_name

let ocaml_type_of_field_type_and_options t optional =
  let type_string = ocaml_type_of_field_type t in
  if optional
  then Printf.sprintf "(%s) option" type_string
  else type_string

let rec parse_fun_of_field_type name = function
  | FT_Empty -> failwith "Unexpected type in parse_fun_of_field_type: empty"
  | FT_Char -> "parse_char"
  | FT_Integer it ->
    Printf.sprintf "parse_uint%d" (int_size it)

  | FT_Enum (module_name, type_name) ->
    Printf.sprintf "%s.parse_%s" module_name type_name

  | FT_IPv4 -> "parse_string 4"
  | FT_IPv6 -> "parse_string 16"
  | FT_String (FixedLen n, _) -> "parse_string " ^ (string_of_int n)
  | FT_String (VarLen int_t, _) ->
    Printf.sprintf "parse_varlen_string \"%s\" parse_uint%d" (quote_string name) (int_size int_t)
  | FT_String (Remaining, _) -> "parse_rem_string"

  | FT_List (FixedLen n, subtype) ->
    Printf.sprintf "parse_list %d (%s)" n (parse_fun_of_field_type name subtype)
  | FT_List (VarLen int_t, subtype) ->
    Printf.sprintf "parse_varlen_list \"%s\" parse_uint%d (%s)" (quote_string name) (int_size int_t) (parse_fun_of_field_type name subtype)
  | FT_List (Remaining, subtype) ->
    Printf.sprintf "parse_rem_list (%s)" (parse_fun_of_field_type name subtype)
  | FT_Container (int_t, subtype) ->
    Printf.sprintf "parse_container \"%s\" parse_uint%d (%s)" (quote_string name) (int_size int_t) (parse_fun_of_field_type name subtype)

  | FT_Custom (module_name, type_name, parse_fun_args) ->
    String.concat " " (((mk_module_prefix module_name) ^ "parse_" ^ type_name)::"~context:ctx"::parse_fun_args)

let rec lwt_parse_fun_of_field_type name = function
  | FT_Empty -> failwith "Unexpected type in lwt_parse_fun_of_field_type: empty"
  | FT_Char -> "lwt_parse_char"
  | FT_Integer it ->
    Printf.sprintf "lwt_parse_uint%d" (int_size it)

  | FT_Enum (module_name, type_name) ->
    Printf.sprintf "%s.lwt_parse_%s" module_name type_name

  | FT_IPv4 -> "lwt_parse_string 4"
  | FT_IPv6 -> "lwt_parse_string 16"
  | FT_String (FixedLen n, _) -> "lwt_parse_string " ^ (string_of_int n)
  | FT_String (VarLen int_t, _) ->
    Printf.sprintf "lwt_parse_varlen_string \"%s\" lwt_parse_uint%d" (quote_string name) (int_size int_t)
  | FT_String (Remaining, _) ->
      Printf.sprintf "lwt_parse_rem_string \"%s\"" (quote_string name)

  | FT_List (FixedLen n, subtype) ->
    Printf.sprintf "lwt_parse_list %d (%s)" n (parse_fun_of_field_type name subtype)
  | FT_List (VarLen int_t, subtype) ->
    Printf.sprintf "lwt_parse_varlen_list \"%s\" lwt_parse_uint%d (%s)" (quote_string name) (int_size int_t) (parse_fun_of_field_type name subtype)
  | FT_List (Remaining, subtype) ->
    Printf.sprintf "lwt_parse_rem_list %s (%s)" name (parse_fun_of_field_type name subtype)
  | FT_Container (int_t, subtype) ->
    Printf.sprintf "lwt_parse_container \"%s\" lwt_parse_uint%d (%s)" (quote_string name) (int_size int_t) (parse_fun_of_field_type name subtype)

  | FT_Custom (module_name, type_name, parse_fun_args) ->
    String.concat " " (((mk_module_prefix module_name) ^ "lwt_parse_" ^ type_name)::" ~context:ctx"::parse_fun_args)


let rec dump_fun_of_field_type = function
  | FT_Empty -> failwith "Unexpected type in dump_fun_of_field_type: empty"
  | FT_Char -> "dump_char"
  | FT_Integer it -> Printf.sprintf "dump_uint%d" (int_size it)

  | FT_Enum (module_name, type_name) ->
    Printf.sprintf "%s.dump_%s" module_name type_name

  | FT_String (VarLen int_t, _) ->
    Printf.sprintf "dump_varlen_string dump_uint%d" (int_size int_t)
  | FT_IPv4
  | FT_IPv6
  | FT_String _ -> "dump_string"

  | FT_List (VarLen int_t, subtype) ->
    Printf.sprintf "dump_varlen_list dump_uint%d (%s)" (int_size int_t) (dump_fun_of_field_type subtype)
  | FT_List (_, subtype) ->
    Printf.sprintf "dump_list (%s)" (dump_fun_of_field_type subtype)
  | FT_Container (int_t, subtype) ->
    Printf.sprintf "dump_container dump_uint%d (%s)" (int_size int_t) (dump_fun_of_field_type subtype)

  | FT_Custom (module_name, type_name, _) -> (mk_module_prefix module_name) ^ "dump_" ^ type_name

let rec print_fun_of_field_type = function
  | FT_Empty -> failwith "Unexpected type in print_fun_of_field_type: empty"
  | FT_Char -> "print_char"
  | FT_Integer it -> Printf.sprintf "print_uint%d" (int_size it)

  | FT_Enum (module_name, type_name) ->
    Printf.sprintf "%s.print_%s" module_name type_name

  | FT_String (_, true) -> "print_binstring"
  | FT_String (_, false) -> "print_string"

  | FT_IPv4 -> "print_ipv4"
  | FT_IPv6 -> "print_ipv6"

  | FT_List (_, subtype) ->
    Printf.sprintf "print_list (%s)" (print_fun_of_field_type subtype)

  | FT_Container (_, subtype) -> print_fun_of_field_type subtype

  | FT_Custom (module_name, type_name, _) -> (mk_module_prefix module_name) ^ "print_" ^ type_name


let remove_empty_fields fields = List.filter (fun (_, ft, _) -> ft <> FT_Empty) fields

let extract_record_parse_params ro =
  let aux accu = function
    | RO_AddParseParameter p -> p::accu
    |RO_NoContextParameter -> accu
  in
  let raw_param_list = List.fold_left aux [] ro in
  let param_list =
    if List.mem RO_NoContextParameter ro
    then List.rev raw_param_list
    else List.rev ("?context:(ctx=None)"::raw_param_list)
  in String.concat " " param_list


let mk_record_desc_type (name, raw_fields, _) =
  let fields = remove_empty_fields raw_fields in
  if fields = []
  then Printf.printf "type %s = unit\n" name
  else begin
    Printf.printf "type %s = {\n" name;
    let aux (fn, ft, fo) =
      Printf.printf "  %s : %s;\n" fn (ocaml_type_of_field_type_and_options ft fo)
    in
    List.iter aux fields;
    print_endline "}\n\n"
  end

let mk_record_parse_fun (name, raw_fields, record_options) =
  let params = extract_record_parse_params record_options in
  let fields = remove_empty_fields raw_fields in
  if fields = []
  then Printf.printf "let parse_%s %s input = ()\n" name params
  else begin
    Printf.printf "let parse_%s %s input =\n" name params;
    let parse_aux (fn, ft, fo) =
      if fo
      then begin
	Printf.printf "  let _%s = if eos input then None\n" fn;
	Printf.printf "            else Some (%s input) in\n" (parse_fun_of_field_type fn ft)
      end
      else Printf.printf "  let _%s = %s input in\n" fn (parse_fun_of_field_type fn ft)
    in
    let mkrec_aux (fn, _, _) = Printf.printf "    %s = _%s;\n" fn fn in
    List.iter parse_aux fields;
    print_endline "  {";
    List.iter mkrec_aux fields;
    print_endline "  }\n"
  end

let mk_record_lwt_parse_fun (name, raw_fields, record_options) =
  let params = extract_record_parse_params record_options in
  let fields = remove_empty_fields raw_fields in
  if fields = []
  then Printf.printf "let lwt_parse_%s %s input = return ()\n" name params
  else begin
    Printf.printf "let lwt_parse_%s %s input =\n" name params;
    let parse_aux (fn, ft, _fo) =
      (* TODO: Really support optional fields *)
      Printf.printf "  %s input >>= fun _%s ->\n" (lwt_parse_fun_of_field_type fn ft) fn
    in
    let mkrec_aux (fn, _, fo) =
      (* TODO: Really support optional fields *)
      if fo
      then Printf.printf "    %s = Some _%s;\n" fn fn
      else Printf.printf "    %s = _%s;\n" fn fn
    in
    List.iter parse_aux fields;
    print_endline "  return {";
    List.iter mkrec_aux fields;
    print_endline "  }\n"
  end

let mk_record_dump_fun (name, raw_fields, _) =
  let fields = remove_empty_fields raw_fields in
  if fields = []
  then Printf.printf "let dump_%s input = \"\"\n" name
  else begin
    Printf.printf "let dump_%s %s =\n" name name;
    let dump_aux (fn, ft, fo) =
      if fo
      then begin
        (Printf.sprintf "  begin\n") ^
        (Printf.sprintf "    match %s.%s with\n" name fn) ^
        (Printf.sprintf "      | None -> \"\"\n") ^
        (Printf.sprintf "      | Some x -> %s x\n" (dump_fun_of_field_type ft)) ^
        (Printf.sprintf "  end")
      end
      else Printf.sprintf "  %s %s.%s" (dump_fun_of_field_type ft) name fn
    in
    print_endline (String.concat " ^ \n" (List.map dump_aux fields));
    print_endline "\n"
  end

let mk_record_print_fun (name, raw_fields, _) =
  let fields = remove_empty_fields raw_fields in
  if fields = []
  then begin
    Printf.printf "let print_%s indent name %s =\n" name name;
    print_endline "  (Printf.sprintf \"%s%s\\n\" indent name)\n";
  end else begin
    let print_aux (fn, ft, fo) =
      if fo
      then begin
        (Printf.sprintf "  begin\n") ^
        (Printf.sprintf "    match %s.%s with\n" name fn) ^
        (Printf.sprintf "      | None -> \"\"\n") ^
        (Printf.sprintf "      | Some x -> %s new_indent \"%s\" x\n" (print_fun_of_field_type ft) (quote_string fn)) ^
        (Printf.sprintf "  end")
      end
      else Printf.sprintf "  (%s new_indent \"%s\" %s.%s)" (print_fun_of_field_type ft) (quote_string fn) name fn
    in
    Printf.printf "let print_%s indent name %s =\n" name name;
    print_endline "  let new_indent = indent ^ \"  \" in";
    print_endline "  (Printf.sprintf \"%s%s {\\n\" indent name) ^";
    print_endline ((String.concat " ^\n" (List.map print_aux fields)) ^ " ^");
    print_endline "  (Printf.sprintf \"%s}\\n\" indent)\n"
  end


let handle_record_desc ?what:(what=All) (desc : record_description) =
  begin
    match what with
      | OnlyTypes | All -> mk_record_desc_type desc;
      | OnlyFuns -> ()
  end;
  match what with
    | OnlyFuns | All ->
      mk_record_parse_fun desc;
      if do_lwt then mk_record_lwt_parse_fun desc;
      mk_record_dump_fun desc;
      mk_record_print_fun desc;
    | OnlyTypes -> ()



(* Choices functions *)

let extract_choice_parse_params ro =
  let aux accu = function
    | CO_AddParseParameter p -> p::accu
    | CO_NoContextParameter
    | CO_ExhaustiveDiscriminatingVals
    | CO_EnrichByDefault -> accu
  in
  let raw_param_list = List.fold_left aux [] ro in
  let param_list =
    if List.mem CO_NoContextParameter ro
    then List.rev raw_param_list
    else List.rev ("?context:(ctx=None)"::raw_param_list)
  in String.concat " " param_list


let mk_choice_type (name, _, _, choices, unparsed_cons, choice_options) =
  let default_enrich = List.mem CO_EnrichByDefault choice_options in
  Printf.printf "let enrich_%s = ref %s\n\n" name (string_of_bool default_enrich);
  Printf.printf "type %s =\n" name;
  let aux (_, cons, choice_type) =
    match choice_type with
    | FT_Empty -> Printf.printf "  | %s\n" cons
    | _ -> Printf.printf "  | %s of %s\n" cons (ocaml_type_of_field_type choice_type)
  in
  List.iter aux choices;
  Printf.printf "  | %s of string\n\n" unparsed_cons

let mk_choice_parse_fun do_lwt (name, discr_module, discr, choices, unparsed_cons, choice_options) =
  let params = extract_choice_parse_params choice_options in
  let fun_name = if do_lwt then "lwt_parse" else "parse" in

  let discr_arg = match discr with
    | Explicit s -> "discriminator "
    | Implicit _ -> ""
  in

  let mk_line (discr_value, cons, choice_type) =
    let value = match do_lwt, choice_type with
      | true, FT_Empty -> Printf.sprintf "return %s" cons
      | true, _ ->
        Printf.sprintf "%s input >>= fun x -> return (%s x)"
          (lwt_parse_fun_of_field_type discr_value choice_type) cons
      | false, FT_Empty -> cons
      | false, _ ->
        Printf.sprintf "%s (%s input)"
          cons (parse_fun_of_field_type discr_value choice_type)
    in
      Printf.printf "      | %s%s -> %s\n" (mk_module_prefix discr_module) discr_value value
  and mk_default unparsed_cons =
    if do_lwt then Printf.sprintf "lwt_parse_rem_string \"%s\" input >>= fun x -> return (%s x)" (quote_string name) unparsed_cons
    else Printf.sprintf "%s (parse_rem_string input)" unparsed_cons
  in

  Printf.printf "let %s_%s %s ?enrich:(enrich=false) %sinput =\n" fun_name name params discr_arg;
  Printf.printf "  if enrich || !enrich_%s then begin\n" name;
  begin
    match discr with
      | Explicit discr_value ->
	Printf.printf "    match discriminator with\n";
      | Implicit discr_expr ->
	Printf.printf "    match ctx with\n";
	Printf.printf "    | None -> %s\n" (mk_default unparsed_cons);
	Printf.printf "    | Some context -> match %s with\n" discr_expr
  end;
  List.iter mk_line choices;
  if not (List.mem CO_ExhaustiveDiscriminatingVals choice_options)
  then Printf.printf "      | _ -> %s\n" (mk_default unparsed_cons);
  Printf.printf "  end else %s\n\n" (mk_default unparsed_cons)


let mk_choice_dump_fun (name, _, _, choices, unparsed_cons, _) =
  Printf.printf "let dump_%s = function\n" name;
  let aux (_, cons, choice_type) = match choice_type with
    | FT_Empty -> Printf.printf "  | %s -> \"\"\n" cons
    | _ -> Printf.printf "  | %s x -> %s x\n" cons (dump_fun_of_field_type choice_type)
  in
  List.iter aux choices;
  Printf.printf "  | %s s -> s\n\n" unparsed_cons

let mk_choice_print_fun (name, _, _, choices, unparsed_cons, _) =
  Printf.printf "let print_%s indent name = function\n" name;
  let aux (_, cons, choice_type) = match choice_type with
    | FT_Empty -> Printf.printf "  | %s -> print_string indent name \"\"\n" cons
    | _ -> Printf.printf "  | %s x -> %s indent name x\n" cons (print_fun_of_field_type choice_type)
  in
  List.iter aux choices;
  Printf.printf "  | %s s -> print_binstring indent name s\n\n" unparsed_cons


let handle_choice_desc ?what:(what=All) (choice : choice_description) =
  begin
    match what with
      | OnlyTypes | All -> mk_choice_type choice;
      | OnlyFuns -> ()
  end;
  match what with
    | OnlyFuns | All ->
      mk_choice_parse_fun false choice;
      if do_lwt then mk_choice_parse_fun true choice;
      mk_choice_dump_fun choice;
      mk_choice_print_fun choice;
    | OnlyTypes -> ()


let _ =
  if do_lwt then begin
    print_endline "open Lwt";
    print_endline "open LwtParsingEngine"
  end;
  print_endline "open ParsingEngine";
  print_endline "open DumpingEngine";
  print_endline "open PrintingEngine\n"



(* Real information about binary records/choices goes after here. *)

