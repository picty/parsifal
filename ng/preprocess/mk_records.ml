open Camlp4
open Camlp4.PreCast
open Syntax

type record_options =
  | DoLwt
(*  | AddParseParameter of string
  | NoContextParameter *)

type field_len =
  | FixedLen of int    (* size in bytes of the field *)
  | VarLen of string   (* name of the integer type used *)
  | Remaining

(* TODO: Add options for lists (AtLeast, AtMost) and for options *)
type field_type =
  | FT_Char
  | FT_Int of string                        (* name of the integer type *)
  | FT_IPv4
  | FT_IPv6
  | FT_String of field_len * bool
  | FT_List of field_len * field_type
  | FT_Container of int * field_type        (* the int corresponds to the size in bytes of the field length *)
  | FT_Custom of (string option) * string


let lid_of_ident _loc = function
  | <:ident< $lid:i$ >> -> i
  | _ -> Loc.raise _loc (Failure "lowercase identifier expected")


let rec length_desc_of_expr _loc = function
  | <:expr< $uid:"Remaining"$ >> -> Remaining
  | <:expr< $uid:"Var"$ $lid:("uint8"|"uint16"|"uint24"|"uint32" as int_t)$ >> -> VarLen int_t
  | <:expr< $uid:"Fixed"$ $int:i$ >> -> FixedLen (int_of_string i)
  | _ -> Loc.raise _loc (Failure "invalid length description")

let rec field_type_of_exprs _loc e d = match e, d with
  | <:ident< $lid:"char"$ >>, None -> FT_Char
  | <:ident< $lid:("uint8"|"uint16"|"uint24"|"uint32" as int_t)$ >>, None -> FT_Int int_t
  | <:ident< $lid:"ipv4"$ >>, None -> FT_IPv4
  | <:ident< $lid:"ipv6"$ >>, None -> FT_IPv6
  | <:ident< $lid:"string"$ >>, None -> FT_String (Remaining, false)
  | <:ident< $lid:"binstring"$ >>, None -> FT_String (Remaining, true)
  | <:ident< $lid:"string"$ >>, Some d -> FT_String (length_desc_of_expr _loc d, false)
  | <:ident< $lid:"binstring"$ >>, Some d -> FT_String (length_desc_of_expr _loc d, true)
  | <:ident< $lid:custom_t$ >>, None -> FT_Custom (None, custom_t)
  | <:ident< $uid:module_name$.$lid:custom_t$ >>, None -> FT_Custom (Some module_name, custom_t)
  | e -> Loc.raise _loc (Failure "invalid identifier for a type")


let rec ocaml_type_of_field_type _loc = function
  | FT_Char -> <:ctyp< $lid:"char"$ >>
  | FT_Int _ -> <:ctyp< $lid:"int"$ >>
  | FT_IPv4 | FT_IPv6 -> <:ctyp< $lid:"string"$ >>
  | FT_String _ -> <:ctyp< $lid:"string"$ >>
  | FT_List (_, subtype) -> <:ctyp< list $ocaml_type_of_field_type _loc subtype$ >>
  | FT_Container (_, subtype) -> ocaml_type_of_field_type _loc subtype
  | FT_Custom (None, n) -> <:ctyp< $lid:n$ >>
  | FT_Custom (Some m, n) -> <:ctyp< $uid:m$.$lid:n$ >>



let mk_record_type (_loc, name, fields, _) =
  let ctyp_fields = List.map (fun (_loc, n, t, _) -> <:ctyp< $lid:n$ : $ocaml_type_of_field_type _loc t$ >> ) fields in
  <:str_item< type $lid:name$ = { $list:ctyp_fields$ } >>



EXTEND Gram
  GLOBAL: expr ctyp str_item;

  field_desc: [[
    type_name = ident -> field_type_of_exprs _loc type_name None
  | type_name = ident ; "(" ; type_decorators = expr; ")" ->
    field_type_of_exprs _loc type_name (Some type_decorators)
  | "("; subtype = SELF; ")"; container_name = ident; "(" ; type_decorators = expr; ")" ->
    match lid_of_ident _loc container_name with
      | "list" -> FT_List (length_desc_of_expr _loc type_decorators, subtype)
      | _ -> Loc.raise _loc (Failure "invalid container type")
  ]];

  field_descs: [[
    f1 = SELF; ";"; f2 = SELF -> f1 @ f2
  | name = ident; ":"; field = field_desc ->
      [_loc, lid_of_ident _loc name, field, false]
  | "optional"; name = ident; ":"; field = field_desc  ->
      [_loc, lid_of_ident _loc name, field, true]
  | -> []
  ]];

  options: [[
    o1 = SELF; ";"; o2 = SELF -> o1 @ o2
  | "lwt" -> [DoLwt]
  | -> []
  ]];

  str_item: [[
    "record_def"; record_name = ident; "["; opts = options; "]"; "="; "{"; fields = field_descs; "}" ->
      let record_descr = (_loc, lid_of_ident _loc record_name, fields, opts) in
      let si1 = mk_record_type record_descr
      in
      <:str_item< $si1$ >>
  ]];
END
;;





















(* (\* Generic functions *\) *)

(* let mk_module_prefix = function *)
(*   | None -> "" *)
(*   | Some module_name -> module_name ^ "." *)



(* (\* Records functions *\) *)

(* let ocaml_type_of_field_type_and_options t optional = *)
(*   let type_string = ocaml_type_of_field_type t in *)
(*   if optional *)
(*   then Printf.sprintf "(%s) option" type_string *)
(*   else type_string *)

(* let rec parse_fun_of_field_type name = function *)
(*   | FT_Char -> "parse_char" *)
(*   | FT_Integer it -> *)
(*     Printf.sprintf "parse_uint%d" (int_size it) *)

(*   | FT_Enum (int_type, module_name, type_name) -> *)
(*     Printf.sprintf "%s.parse_%s parse_uint%d" module_name type_name (int_size int_type) *)

(*   | FT_IPv4 -> "parse_string 4" *)
(*   | FT_IPv6 -> "parse_string 16" *)
(*   | FT_String (FixedLen n, _) -> "parse_string " ^ (string_of_int n) *)
(*   | FT_String (VarLen int_t, _) -> *)
(*     Printf.sprintf "parse_varlen_string \"%s\" parse_uint%d" (quote_string name) (int_size int_t) *)
(*   | FT_String (Remaining, _) -> "parse_rem_string" *)

(*   | FT_List (FixedLen n, subtype) -> *)
(*     Printf.sprintf "parse_list %d (%s)" n (parse_fun_of_field_type name subtype) *)
(*   | FT_List (VarLen int_t, subtype) -> *)
(*     Printf.sprintf "parse_varlen_list \"%s\" parse_uint%d (%s)" (quote_string name) (int_size int_t) (parse_fun_of_field_type name subtype) *)
(*   | FT_List (Remaining, subtype) -> *)
(*     Printf.sprintf "parse_rem_list (%s)" (parse_fun_of_field_type name subtype) *)
(*   | FT_Container (int_t, subtype) -> *)
(*     Printf.sprintf "parse_container \"%s\" parse_uint%d (%s)" (quote_string name) (int_size int_t) (parse_fun_of_field_type name subtype) *)

(*   | FT_Custom (module_name, type_name, parse_fun_args) -> *)
(*     String.concat " " (((mk_module_prefix module_name) ^ "parse_" ^ type_name)::"~context:ctx"::parse_fun_args) *)

(* let rec lwt_parse_fun_of_field_type name = function *)
(*   | FT_Char -> "lwt_parse_char" *)
(*   | FT_Integer it -> *)
(*     Printf.sprintf "lwt_parse_uint%d" (int_size it) *)

(*   | FT_Enum (int_type, module_name, type_name) -> *)
(*     Printf.sprintf "%s.lwt_parse_%s lwt_parse_uint%d" module_name type_name (int_size int_type) *)

(*   | FT_IPv4 -> "lwt_parse_string 4" *)
(*   | FT_IPv6 -> "lwt_parse_string 16" *)
(*   | FT_String (FixedLen n, _) -> "lwt_parse_string " ^ (string_of_int n) *)
(*   | FT_String (VarLen int_t, _) -> *)
(*     Printf.sprintf "lwt_parse_varlen_string \"%s\" lwt_parse_uint%d" (quote_string name) (int_size int_t) *)
(*   | FT_String (Remaining, _) -> *)
(*       Printf.sprintf "lwt_parse_rem_string \"%s\"" (quote_string name) *)

(*   | FT_List (FixedLen n, subtype) -> *)
(*     Printf.sprintf "lwt_parse_list %d (%s)" n (parse_fun_of_field_type name subtype) *)
(*   | FT_List (VarLen int_t, subtype) -> *)
(*     Printf.sprintf "lwt_parse_varlen_list \"%s\" lwt_parse_uint%d (%s)" (quote_string name) (int_size int_t) (parse_fun_of_field_type name subtype) *)
(*   | FT_List (Remaining, subtype) -> *)
(*     Printf.sprintf "lwt_parse_rem_list %s (%s)" name (parse_fun_of_field_type name subtype) *)
(*   | FT_Container (int_t, subtype) -> *)
(*     Printf.sprintf "lwt_parse_container \"%s\" lwt_parse_uint%d (%s)" (quote_string name) (int_size int_t) (parse_fun_of_field_type name subtype) *)

(*   | FT_Custom (module_name, type_name, parse_fun_args) -> *)
(*     String.concat " " (((mk_module_prefix module_name) ^ "lwt_parse_" ^ type_name)::" ~context:ctx"::parse_fun_args) *)


(* let rec dump_fun_of_field_type = function *)
(*   | FT_Char -> "dump_char" *)
(*   | FT_Integer it -> Printf.sprintf "dump_uint%d" (int_size it) *)

(*   | FT_Enum (int_type, module_name, type_name) -> *)
(*     Printf.sprintf "%s.dump_%s dump_uint%d" module_name type_name (int_size int_type) *)

(*   | FT_String (VarLen int_t, _) -> *)
(*     Printf.sprintf "dump_varlen_string dump_uint%d" (int_size int_t) *)
(*   | FT_IPv4 *)
(*   | FT_IPv6 *)
(*   | FT_String _ -> "dump_string" *)

(*   | FT_List (VarLen int_t, subtype) -> *)
(*     Printf.sprintf "dump_varlen_list dump_uint%d (%s)" (int_size int_t) (dump_fun_of_field_type subtype) *)
(*   | FT_List (_, subtype) -> *)
(*     Printf.sprintf "dump_list (%s)" (dump_fun_of_field_type subtype) *)
(*   | FT_Container (int_t, subtype) -> *)
(*     Printf.sprintf "dump_container dump_uint%d (%s)" (int_size int_t) (dump_fun_of_field_type subtype) *)

(*   | FT_Custom (module_name, type_name, _) -> (mk_module_prefix module_name) ^ "dump_" ^ type_name *)

(* let rec print_fun_of_field_type = function *)
(*   | FT_Char -> "print_char" *)
(*   | FT_Integer it -> Printf.sprintf "print_uint %d" (int_size it) *)

(*   | FT_Enum (int_type, module_name, type_name) -> *)
(*     Printf.sprintf "%s.print_%s %d" module_name type_name ((int_size int_type) / 4) *)

(*   | FT_String (_, true) -> "print_binstring" *)
(*   | FT_String (_, false) -> "print_string" *)

(*   | FT_IPv4 -> "print_ipv4" *)
(*   | FT_IPv6 -> "print_ipv6" *)

(*   | FT_List (_, subtype) -> *)
(*     Printf.sprintf "print_list (%s)" (print_fun_of_field_type subtype) *)

(*   | FT_Container (_, subtype) -> print_fun_of_field_type subtype *)

(*   | FT_Custom (module_name, type_name, _) -> (mk_module_prefix module_name) ^ "print_" ^ type_name *)


(* let extract_record_parse_params ro = *)
(*   let aux accu = function *)
(*     | RO_AddParseParameter p -> p::accu *)
(*     |RO_NoContextParameter -> accu *)
(*   in *)
(*   let raw_param_list = List.fold_left aux [] ro in *)
(*   let param_list = *)
(*     if List.mem RO_NoContextParameter ro *)
(*     then List.rev raw_param_list *)
(*     else List.rev ("?context:(ctx=None)"::raw_param_list) *)
(*   in String.concat " " param_list *)


(* let mk_record_desc_type (name, raw_fields, _) = *)
(*   if fields = [] *)
(*   then Printf.printf "type %s = unit\n" name *)
(*   else begin *)
(*     Printf.printf "type %s = {\n" name; *)
(*     let aux (fn, ft, fo) = *)
(*       Printf.printf "  %s : %s;\n" fn (ocaml_type_of_field_type_and_options ft fo) *)
(*     in *)
(*     List.iter aux fields; *)
(*     print_endline "}\n\n" *)
(*   end *)

(* let mk_record_parse_fun (name, raw_fields, record_options) = *)
(*   let params = extract_record_parse_params record_options in *)
(*   if fields = [] *)
(*   then Printf.printf "let parse_%s %s input = ()\n" name params *)
(*   else begin *)
(*     Printf.printf "let parse_%s %s input =\n" name params; *)
(*     let parse_aux (fn, ft, fo) = *)
(*       if fo *)
(*       then begin *)
(* 	Printf.printf "  let _%s = if eos input then None\n" fn; *)
(* 	Printf.printf "            else Some (%s input) in\n" (parse_fun_of_field_type fn ft) *)
(*       end *)
(*       else Printf.printf "  let _%s = %s input in\n" fn (parse_fun_of_field_type fn ft) *)
(*     in *)
(*     let mkrec_aux (fn, _, _) = Printf.printf "    %s = _%s;\n" fn fn in *)
(*     List.iter parse_aux fields; *)
(*     print_endline "  {"; *)
(*     List.iter mkrec_aux fields; *)
(*     print_endline "  }\n" *)
(*   end *)

(* let mk_record_lwt_parse_fun (name, raw_fields, record_options) = *)
(*   let params = extract_record_parse_params record_options in *)
(*   if fields = [] *)
(*   then Printf.printf "let lwt_parse_%s %s input = return ()\n" name params *)
(*   else begin *)
(*     Printf.printf "let lwt_parse_%s %s input =\n" name params; *)
(*     let parse_aux (fn, ft, _fo) = *)
(*       (\* TODO: Really support optional fields *\) *)
(*       Printf.printf "  %s input >>= fun _%s ->\n" (lwt_parse_fun_of_field_type fn ft) fn *)
(*     in *)
(*     let mkrec_aux (fn, _, fo) = *)
(*       (\* TODO: Really support optional fields *\) *)
(*       if fo *)
(*       then Printf.printf "    %s = Some _%s;\n" fn fn *)
(*       else Printf.printf "    %s = _%s;\n" fn fn *)
(*     in *)
(*     List.iter parse_aux fields; *)
(*     print_endline "  return {"; *)
(*     List.iter mkrec_aux fields; *)
(*     print_endline "  }\n" *)
(*   end *)

(* let mk_record_dump_fun (name, raw_fields, _) = *)
(*   if fields = [] *)
(*   then Printf.printf "let dump_%s input = \"\"\n" name *)
(*   else begin *)
(*     Printf.printf "let dump_%s %s =\n" name name; *)
(*     let dump_aux (fn, ft, fo) = *)
(*       if fo *)
(*       then begin *)
(*         (Printf.sprintf "  begin\n") ^ *)
(*         (Printf.sprintf "    match %s.%s with\n" name fn) ^ *)
(*         (Printf.sprintf "      | None -> \"\"\n") ^ *)
(*         (Printf.sprintf "      | Some x -> %s x\n" (dump_fun_of_field_type ft)) ^ *)
(*         (Printf.sprintf "  end") *)
(*       end *)
(*       else Printf.sprintf "  %s %s.%s" (dump_fun_of_field_type ft) name fn *)
(*     in *)
(*     print_endline (String.concat " ^ \n" (List.map dump_aux fields)); *)
(*     print_endline "\n" *)
(*   end *)

(* let mk_record_print_fun (name, raw_fields, _) = *)
(*   if fields = [] *)
(*   then begin *)
(*     Printf.printf "let print_%s indent name %s =\n" name name; *)
(*     print_endline "  (Printf.sprintf \"%s%s\\n\" indent name)\n"; *)
(*   end else begin *)
(*     let print_aux (fn, ft, fo) = *)
(*       if fo *)
(*       then begin *)
(*         (Printf.sprintf "  begin\n") ^ *)
(*         (Printf.sprintf "    match %s.%s with\n" name fn) ^ *)
(*         (Printf.sprintf "      | None -> \"\"\n") ^ *)
(*         (Printf.sprintf "      | Some x -> %s new_indent \"%s\" x\n" (print_fun_of_field_type ft) (quote_string fn)) ^ *)
(*         (Printf.sprintf "  end") *)
(*       end *)
(*       else Printf.sprintf "  (%s new_indent \"%s\" %s.%s)" (print_fun_of_field_type ft) (quote_string fn) name fn *)
(*     in *)
(*     Printf.printf "let print_%s indent name %s =\n" name name; *)
(*     print_endline "  let new_indent = indent ^ \"  \" in"; *)
(*     print_endline "  (Printf.sprintf \"%s%s {\\n\" indent name) ^"; *)
(*     print_endline ((String.concat " ^\n" (List.map print_aux fields)) ^ " ^"); *)
(*     print_endline "  (Printf.sprintf \"%s}\\n\" indent)\n" *)
(*   end *)


(* let handle_record_desc ?what:(what=All) (desc : record_description) = *)
(*   begin *)
(*     match what with *)
(*       | OnlyTypes | All -> mk_record_desc_type desc; *)
(*       | OnlyFuns -> () *)
(*   end; *)
(*   match what with *)
(*     | OnlyFuns | All -> *)
(*       mk_record_parse_fun desc; *)
(*       if do_lwt then mk_record_lwt_parse_fun desc; *)
(*       mk_record_dump_fun desc; *)
(*       mk_record_print_fun desc; *)
(*     | OnlyTypes -> () *)














(* let pat_lid _loc name = <:patt< $lid:name$ >> *)
(* let pat_uid _loc name = <:patt< $uid:name$ >> *)
(* let exp_int _loc i = <:expr< $int:i$ >> *)
(* let exp_str _loc s = <:expr< $str:s$ >> *)
(* let exp_lid _loc name = <:expr< $lid:name$ >> *)
(* let exp_uid _loc name = <:expr< $uid:name$ >> *)

(* let mk_ctors (_loc, name, enum, unknown) = *)
(*   let ctors = List.map (fun (_loc, _, n, _) -> <:ctyp< $uid:n$ >> ) enum in *)

(*   let suffix_choice = match unknown with *)
(*     | _loc, UnknownVal v -> [ <:ctyp<  $ <:ctyp< $uid:v$ >> $  of  int  >> ] *)
(*     | _ -> [] *)
(*   in *)

(*   let ctyp_ctors = ctors@suffix_choice in *)
(*   let constructors = Ast.TySum (_loc, Ast.tyOr_of_list ctyp_ctors) in *)
(*   <:str_item< type $lid:name$ = $constructors$ >> *)


(* let mk_string_of_enum (_loc, name, enum, unknown) = *)
(*   let mk_case (_loc, _, n, d) = *)
(*     let p, e = ( pat_uid _loc n, <:expr< $str:d$ >> ) in *)
(*     <:match_case< $p$ -> $e$ >> *)
(*   in *)
(*   let _cases = List.map mk_case enum in *)
(*   let cases = match unknown with *)
(*     | _loc, UnknownVal v -> *)
(*       let p = <:patt<  $pat_uid _loc v$  $pat_lid _loc "i"$  >> *)
(*       and e = <:expr< $str:"Unknown " ^ name ^ " ("$ ^ (string_of_int i) ^ $str:")"$ >> *)
(*       in _cases@[ <:match_case< $p$ -> $e$ >> ] *)
(*     | _ -> _cases *)
(*   in *)
(*   let body = <:expr< fun [ $list:cases$ ] >> *)
(*   and fun_name = pat_lid _loc ("string_of_" ^ name) in *)
(*   let bindings = <:binding< $pat:fun_name$ = $exp:body$ >> in *)
(*   <:str_item< value $bindings$ >> *)


(* let mk_int_of_enum (_loc, name, enum, unknown) = *)
(*   let mk_case (_loc, v, n, _) = *)
(*     let p, e = ( pat_uid _loc n, exp_int _loc v ) in *)
(*     <:match_case< $p$ -> $e$ >> *)
(*   in *)
(*   let _cases = List.map mk_case enum in *)
(*   let cases = match unknown with *)
(*     | _loc, UnknownVal v -> *)
(*       let p = <:patt<  $pat_uid _loc v$ $pat_lid _loc "i"$ >> *)
(*       and e = exp_lid _loc "i" *)
(*       in _cases@[ <:match_case< $p$ -> $e$ >> ] *)
(*     | _ -> _cases *)
(*   in *)
(*   let body = <:expr< fun [ $list:cases$ ] >> *)
(*   and fun_name = pat_lid _loc ("int_of_" ^ name) in *)
(*   let bindings = <:binding< $pat:fun_name$ = $exp:body$ >> in *)
(*   <:str_item< value $bindings$ >> *)


(* let mk_enum_of_int (_loc, name, enum, unknown) = *)
(*   let mk_case (_loc, v, n, _) = *)
(*     let p, e = ( <:patt< $int:v$ >>, <:expr< $uid:n$ >> ) in *)
(*     <:match_case< $p$ -> $e$ >> *)
(*   in *)
(*   let _cases = List.map mk_case enum in *)
(*   let cases = match unknown with *)
(*     | _loc, UnknownVal v -> *)
(*       let p = pat_lid _loc "i" *)
(*       and e = <:expr< $exp_uid _loc v$  $exp_lid _loc "i"$  >> *)
(*       in _cases@[ <:match_case< $p$ -> $e$ >> ] *)
(*     | _loc, Exception e -> *)
(*       let p = <:patt< _ >> *)
(*       and e = <:expr< raise $exp_uid _loc e$ >> *)
(*       in _cases@[ <:match_case< $p$ -> $e$ >> ] *)
(*   in *)
(*   let body = <:expr< fun [ $list:cases$ ] >> *)
(*   and fun_name = pat_lid _loc (name ^ "_of_int") in *)
(*   let bindings = <:binding< $pat:fun_name$ = $exp:body$ >> in *)
(*   <:str_item< value $bindings$ >> *)


(* let mk_enum_of_string (_loc, name, enum, unknown) = *)
(*   let mk_case (_loc, _, n, d) = *)
(*     let p, e = ( <:patt< $str:d$ >>, <:expr< $uid:n$ >> ) in *)
(*     <:match_case< $p$ -> $e$ >> *)
(*   in *)
(*   let _cases = List.map mk_case enum in *)
(*   let cases = *)
(*     let p = pat_lid _loc "s" *)
(*     and e = <:expr< $ <:expr< $lid:(name ^ "_of_int")$ >> $  ( $ <:expr< $lid:"int_of_string"$ >> $  $ <:expr< $lid:"s"$ >> $ )  >> *)
(*     in _cases@[ <:match_case< $p$ -> $e$ >> ] *)
(*   in *)
(*   let body = <:expr< fun [ $list:cases$ ] >> *)
(*   and fun_name = pat_lid _loc (name ^ "_of_string") in *)
(*   let bindings = <:binding< $pat:fun_name$ = $exp:body$ >> in *)
(*   <:str_item< value $bindings$ >> *)


(* let mk_parse_dump_print_funs opts (_loc, name, _, _) = *)
(*   <:str_item< value $ <:binding< $pat:pat_lid _loc ("parse_" ^ name)$ $pat:pat_lid _loc "parse_int"$ $pat:pat_lid _loc "input"$ = *)
(*        $exp: <:expr< $exp_lid _loc (name ^ "_of_int")$ (parse_int input) >> $ >> $ >>, *)

(*   begin *)
(*     if List.mem DoLwt opts then *)
(*       <:str_item< value $ <:binding< $pat:pat_lid _loc ("lwt_parse_" ^ name)$ $pat:pat_lid _loc "lwt_parse_int"$ $pat:pat_lid _loc "input"$ = *)
(*            $exp: <:expr< Lwt.bind (lwt_parse_int input) (fun x -> Lwt.return ( $ <:expr< $exp_lid _loc (name ^ "_of_int")$ x >> $ ) ) >> $ >> $ >> *)
(*     else <:str_item< >> *)
(*   end, *)

(*   <:str_item< value $ <:binding< $pat:pat_lid _loc ("dump_" ^ name)$ $pat:pat_lid _loc "dump_int"$ $pat:pat_lid _loc "v"$ = *)
(*        $exp: <:expr< dump_int ( $exp_lid _loc ("int_of_" ^ name)$ v) >> $ >> $ >>, *)

(*   <:str_item< value $ <:binding< $pat:pat_lid _loc ("print_" ^ name)$ = *)
(*        $exp: <:expr< PrintingEngine.print_enum $exp_lid _loc ("string_of_" ^ name)$ $exp_lid _loc ("int_of_" ^ name)$ >> $ >> $ >> *)



