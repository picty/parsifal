open Camlp4
open Camlp4.PreCast
open Syntax


(* Common camlp4 functions *)

let uid_of_ident _loc = function
  | <:ident< $uid:id$ >> -> id
  | _ -> Loc.raise _loc (Failure "uppercase identifier expected")

let lid_of_ident _loc = function
  | <:ident< $lid:id$ >> -> id
  | _ -> Loc.raise _loc (Failure "lowercase identifier expected")

let pat_lid _loc name = <:patt< $lid:name$ >>
let pat_uid _loc name = <:patt< $uid:name$ >>
let exp_int _loc i = <:expr< $int:i$ >>
let exp_str _loc s = <:expr< $str:s$ >>
let exp_lid _loc name = <:expr< $lid:name$ >>
let exp_uid _loc name = <:expr< $uid:name$ >>
let ctyp_uid _loc name = <:ctyp< $uid:name$ >>

let exp_qname _loc m n = match m with
  | None -> <:expr< $lid:n$ >>
  | Some module_name -> <:expr< $uid:module_name$.$lid:n$ >>

let rec exp_of_list _loc = function
  | [] -> <:expr< $uid:"[]"$ >>
  | e::r -> <:expr< $uid:"::"$ $e$ $exp_of_list _loc r$ >>



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
  | FT_Container of string * field_type     (* the string corresponds to the integer type for the field length *)
  | FT_Custom of (string option) * string


(* To-be-processed file parsing *)

let rec field_type_of_ident _loc = function
  | <:ident< $lid:"char"$ >> -> FT_Char
  | <:ident< $lid:("uint8"|"uint16"|"uint24"|"uint32" as int_t)$ >> -> FT_Int int_t
  | <:ident< $lid:"ipv4"$ >> -> FT_IPv4
  | <:ident< $lid:"ipv6"$ >> -> FT_IPv6
  | <:ident< $lid:"string"$ >> -> FT_String (Remaining, false)
  | <:ident< $lid:"binstring"$ >> -> FT_String (Remaining, true)
  | <:ident< $lid:custom_t$ >> -> FT_Custom (None, custom_t)
  | <:ident< $uid:module_name$.$lid:custom_t$ >> -> FT_Custom (Some module_name, custom_t)
  | e -> Loc.raise _loc (Failure "invalid identifier for a type")

let rec field_type_of_complex_stuff _loc _name decorator subtype =
  let name = lid_of_ident _loc _name in
  match name, decorator, subtype with
    | "list", None, Some t -> FT_List (Remaining, t)
    | "list", Some <:expr< $int: i$ >>, Some t -> FT_List (FixedLen (int_of_string i), t)
    | "list", Some <:expr< $lid:("uint8"|"uint16"|"uint24"|"uint32" as int_t)$ >>, Some t -> FT_List (VarLen int_t, t)
    | "list", _, _ -> Loc.raise _loc (Failure "invalid list type")

    | "container", Some <:expr< $str:("uint8"|"uint16"|"uint24"|"uint32" as int_t)$ >>, Some t -> FT_Container (int_t, t)
    | "container", _, _ -> Loc.raise _loc (Failure "invalid container type")

    | "string", Some <:expr< $int:i$ >>, None -> FT_String (FixedLen (int_of_string i), false)
    | "binstring", Some <:expr< $int:i$ >>, None -> FT_String (FixedLen (int_of_string i), true)
    | "string", Some <:expr< $lid:("uint8"|"uint16"|"uint24"|"uint32" as int_t)$ >>, None -> FT_String (VarLen int_t, false)
    | "binstring", Some <:expr< $lid:("uint8"|"uint16"|"uint24"|"uint32" as int_t)$ >>, None -> FT_String (VarLen int_t, true)
    | ("string" | "binstring"), _, _ -> Loc.raise _loc (Failure "invalid string type")

    | n, _, _ -> Loc.raise _loc (Failure ("unknown meta-type name: " ^ n))


(* Type creation *)

let rec _ocaml_type_of_field_type _loc = function
  | FT_Char -> <:ctyp< $lid:"char"$ >>
  | FT_Int _ -> <:ctyp< $lid:"int"$ >>
  | FT_IPv4 | FT_IPv6 -> <:ctyp< $lid:"string"$ >>
  | FT_String _ -> <:ctyp< $lid:"string"$ >>
  | FT_List (_, subtype) -> <:ctyp< list $_ocaml_type_of_field_type _loc subtype$ >>
  | FT_Container (_, subtype) -> _ocaml_type_of_field_type _loc subtype
  | FT_Custom (None, n) -> <:ctyp< $lid:n$ >>
  | FT_Custom (Some m, n) -> <:ctyp< $uid:m$.$lid:n$ >>


let ocaml_type_of_field_type _loc t opt =
  let real_t = _ocaml_type_of_field_type _loc t in
  if opt then <:ctyp< option $real_t$ >> else real_t

let mk_record_type (_loc, name, fields, _) =
  let ctyp_fields = List.map (fun (_loc, n, t, optional) -> <:ctyp< $lid:n$ : $ocaml_type_of_field_type _loc t optional$ >> ) fields in
  <:str_item< type $lid:name$ = { $list:ctyp_fields$ } >>


(* Parse function *)

let rec parse_fun_of_field_type _loc name t =
  let mk_pf fname = <:expr< $uid:"ParsingEngine"$.$lid:fname$ >> in
  match t with
    | FT_Char -> mk_pf "parse_char"
    | FT_Int int_t -> mk_pf  ("parse_" ^ int_t)
    | FT_IPv4 -> <:expr< $mk_pf "parse_string"$ $exp_int _loc "4"$ >>
    | FT_IPv6 -> <:expr< $mk_pf "parse_string"$ $exp_int _loc "16"$ >>

    | FT_String (FixedLen n, _) -> <:expr< $mk_pf "parse_string"$ $exp_int _loc (string_of_int n)$ >>
    | FT_String (VarLen int_t, _) ->
      <:expr< $mk_pf "parse_varlen_string"$ $exp_str _loc name$ $mk_pf ("parse_" ^ int_t)$ >>
    | FT_String (Remaining, _) -> mk_pf "parse_rem_string"

    | FT_List (FixedLen n, subtype) ->
      <:expr< $mk_pf "parse_list"$ $exp_int _loc (string_of_int n)$ $parse_fun_of_field_type _loc name subtype$ >>
    | FT_List (VarLen int_t, subtype) ->
      <:expr< $mk_pf "parse_varlen_list"$ $exp_str _loc name$ $mk_pf ("parse_" ^ int_t)$ $parse_fun_of_field_type _loc name subtype$ >>
    | FT_List (Remaining, subtype) ->
      <:expr< $mk_pf "parse_rem_list"$ $parse_fun_of_field_type _loc name subtype$ >>
    | FT_Container (int_t, subtype) ->
      <:expr< $mk_pf "parse_container"$ $exp_str _loc name$ $mk_pf ("parse_" ^ int_t)$ $parse_fun_of_field_type _loc name subtype$ >>

    | FT_Custom (m, n) -> exp_qname _loc m ("parse_" ^ n)


let mk_record_parse_fun (_loc, name, fields, _) =
  let rec mk_body = function
    | [] ->
      let field_assigns = List.map (fun (_loc, n, _, _) ->
	<:rec_binding< $lid:n$ = $exp:exp_lid _loc ("_" ^ n)$ >> ) fields
      in <:expr< { $list:field_assigns$ } >>
    | (_loc, n, t, false)::r ->
      let tmp = mk_body r in
      <:expr< let $lid:("_" ^ n)$ = $parse_fun_of_field_type _loc n t$ input in $tmp$ >>
    | (_loc, n, t, true)::r ->
      let tmp = mk_body r in
      <:expr< let $lid:("_" ^ n)$ = ParsingEngine.try_parse $parse_fun_of_field_type _loc n t$ input in $tmp$ >>
  in

  let body = mk_body fields in
  <:str_item< value $ <:binding< $pat:pat_lid _loc ("parse_" ^ name)$ $pat_lid _loc "input"$ = $exp:body$ >> $ >>


(* Lwt Parse function *)

let rec lwt_parse_fun_of_field_type _loc name t =
  let mk_pf fname = <:expr< $uid:"LwtParsingEngine"$.$lid:fname$ >> in
  match t with
  | FT_Char -> mk_pf "lwt_parse_char"
  | FT_Int int_t -> mk_pf ("lwt_parse_" ^ int_t)
  | FT_IPv4 -> <:expr< $mk_pf "lwt_parse_string"$ $exp_int _loc "4"$ >>
  | FT_IPv6 -> <:expr< $mk_pf "lwt_parse_string"$ $exp_int _loc "16"$ >>

  | FT_String (FixedLen n, _) -> <:expr< $mk_pf "lwt_parse_string"$ $exp_int _loc (string_of_int n)$ >>
  | FT_String (VarLen int_t, _) ->
    <:expr< $mk_pf "lwt_parse_varlen_string"$ $exp_str _loc name$ $mk_pf ("lwt_parse_" ^ int_t)$ >>
  | FT_String (Remaining, _) -> mk_pf "lwt_parse_rem_string"

  | FT_List (FixedLen n, subtype) ->
    <:expr< $mk_pf "lwt_parse_list"$ $exp_int _loc (string_of_int n)$ $lwt_parse_fun_of_field_type _loc name subtype$ >>
  | FT_List (VarLen int_t, subtype) ->
    <:expr< $mk_pf "lwt_parse_varlen_list"$ $exp_str _loc name$ $mk_pf ("lwt_parse_" ^ int_t)$
                                                   $lwt_parse_fun_of_field_type _loc name subtype$ >>
  | FT_List (Remaining, subtype) ->
    <:expr< $mk_pf "lwt_parse_rem_list"$ $lwt_parse_fun_of_field_type _loc name subtype$ >>
  | FT_Container (int_t, subtype) ->
    <:expr< $mk_pf "lwt_parse_container"$ $exp_str _loc name$ $mk_pf ("lwt_parse_" ^ int_t)$
                                                 $lwt_parse_fun_of_field_type _loc name subtype$ >>

  | FT_Custom (m, n) -> exp_qname _loc m ("lwt_parse_" ^ n)


let mk_record_lwt_parse_fun (_loc, name, fields, _) =
  let rec mk_body = function
    | [] ->
      let field_assigns = List.map (fun (_loc, n, _, _) ->
	<:rec_binding< $lid:n$ = $exp:exp_lid _loc ("_" ^ n)$ >> ) fields
      in <:expr< Lwt.return { $list:field_assigns$ } >>
    | (_loc, n, t, false)::r ->
      let tmp = mk_body r in
      <:expr< Lwt.bind ($lwt_parse_fun_of_field_type _loc n t$ input) (fun $lid:("_" ^ n)$ -> $tmp$ ) >>
    | (_loc, n, t, true)::r ->
      (* TODO? *)
      let tmp = mk_body r in
      <:expr< Lwt.bind ($lwt_parse_fun_of_field_type _loc n t$ input) (fun $lid:("_" ^ n)$ -> $tmp$ ) >>
  in

  let body = mk_body fields in
  <:str_item< value $ <:binding< $pat:pat_lid _loc ("lwt_parse_" ^ name)$ $pat_lid _loc "input"$ = $exp:body$ >> $ >>


(* Dump function *)

let rec dump_fun_of_field_type _loc t =
  let mk_df fname = <:expr< $uid:"DumpingEngine"$.$lid:fname$ >> in
  match t with
    | FT_Char -> mk_df "dump_char"
    | FT_Int int_t -> mk_df  ("dump_" ^ int_t)

    | FT_String (VarLen int_t, _) ->
      <:expr< $mk_df "dump_varlen_string"$ $mk_df ("dump_" ^ int_t)$ >>
    | FT_IPv4
    | FT_IPv6
    | FT_String _ -> mk_df "dump_string"

    | FT_List (VarLen int_t, subtype) ->
      <:expr< $mk_df "dump_varlen_list"$ $mk_df ("dump_" ^ int_t)$ $dump_fun_of_field_type _loc subtype$ >>
    | FT_List (_, subtype) ->
      <:expr< $mk_df "dump_list"$ $dump_fun_of_field_type _loc subtype$ >>
    | FT_Container (int_t, subtype) ->
      <:expr< $mk_df "dump_container"$ $mk_df ("dump_" ^ int_t)$ $dump_fun_of_field_type _loc subtype$ >>

    | FT_Custom (m, n) -> exp_qname _loc m ("dump_" ^ n)


let mk_record_dump_fun (_loc, name, fields, _) =
  let dump_one_field = function
      (_loc, n, t, false) ->
      <:expr< $dump_fun_of_field_type _loc t$ $lid:name$.$lid:n$ >>
    | (_loc, n, t, true) ->
      <:expr< DumpingEngine.try_dump $dump_fun_of_field_type _loc t$ $lid:name$.$lid:n$ >>
  in
  let fields_dumped_expr = exp_of_list _loc (List.map dump_one_field fields) in
  let body =
    <:expr< let $lid:"fields_dumped"$ = $fields_dumped_expr$ in
	    String.concat "" fields_dumped >>
  in
  <:str_item< value $ <:binding< $pat:pat_lid _loc ("dump_" ^ name)$ $pat_lid _loc name$ = $exp:body$ >> $ >>


(* Print function *)

let rec print_fun_of_field_type _loc t =
  let mk_pf fname = <:expr< $uid:"PrintingEngine"$.$lid:fname$ >> in
  match t with
    | FT_Char -> mk_pf "print_char"
    | FT_Int int_t -> mk_pf  ("print_" ^ int_t)

    | FT_String (_, false) -> mk_pf "print_string"
    | FT_String (_, true) -> mk_pf "print_binstring"
    | FT_IPv4 -> mk_pf "print_ipv4"
    | FT_IPv6 -> mk_pf "print_ipv6"

    | FT_List (_, subtype) ->
      <:expr< $mk_pf "print_list"$ $print_fun_of_field_type _loc subtype$ >>
    | FT_Container (_, subtype) -> print_fun_of_field_type _loc subtype
    | FT_Custom (m, n) -> exp_qname _loc m ("print_" ^ n)


let mk_record_print_fun (_loc, name, fields, _) =
  let print_one_field = function
      (_loc, n, t, false) ->
	<:expr< $print_fun_of_field_type _loc t$ new_indent $str:n$ $lid:name$.$lid:n$ >>
    | (_loc, n, t, true) ->
	<:expr< PrintingEngine.try_print $print_fun_of_field_type _loc t$ new_indent $str:n$ $lid:name$.$lid:n$ >>
  in
  let fields_printed_expr = exp_of_list _loc (List.map print_one_field fields) in
  let body =
    <:expr< let new_indent = indent ^ "  " in
	    let $lid:"fields_printed"$ = $fields_printed_expr$ in
	    indent ^ name ^ " {\\n" ^
	    (String.concat "" fields_printed) ^
	    indent ^ "}\\n" >>
  in
  <:str_item< value $ <:binding< $pat:pat_lid _loc ("print_" ^ name)$ indent name $pat_lid _loc name$ = $exp:body$ >> $ >>


EXTEND Gram
  GLOBAL: expr ctyp str_item;

  field_desc: [[
    type_name = ident -> field_type_of_ident _loc type_name
  | "("; t = SELF; ")" -> t

  | container = ident; "of"; t = SELF ->
    field_type_of_complex_stuff _loc container None (Some t)
  | container = ident; "("; e = expr; ")"; "of"; t = SELF ->
    field_type_of_complex_stuff _loc container (Some e) (Some t)

  | type_name = ident; "("; e = expr; ")" ->
    field_type_of_complex_stuff _loc type_name (Some e) None
  ]];

  field_descs: [[
    f1 = SELF; ";"; f2 = SELF -> f1 @ f2
  | name = ident; ":"; field = field_desc ->
      [_loc, lid_of_ident _loc name, field, false]
  | "optional"; name = ident; ":"; field = field_desc  ->
      [_loc, lid_of_ident _loc name, field, true]
  | -> []
  ]];

  (* TODO: lwt and exact should be simple lids and not keywords *)

  options: [[
    o1 = SELF; ";"; o2 = SELF -> o1 @ o2
  | "lwt" -> [DoLwt]
  | -> []
  ]];

  str_item: [[
    "record_def"; record_name = ident; "["; opts = options; "]"; "="; "{"; fields = field_descs; "}" ->
      let record_descr = (_loc, lid_of_ident _loc record_name, fields, opts) in
      let si1 = mk_record_type record_descr
      and si2 = mk_record_parse_fun record_descr
      (* TODO: exact and lwt option *)
      and si3 = mk_record_lwt_parse_fun record_descr
      and si4 = mk_record_dump_fun record_descr
      and si5 = mk_record_print_fun record_descr
      in
      <:str_item< $si1$; $si2$; $si3$; $si4$; $si5$ >>
  ]];
END
;;
