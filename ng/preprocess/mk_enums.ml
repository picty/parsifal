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


type unknown_behaviour =
  | UnknownVal of string
  | Exception of string

type enum_option =
  | DoLwt

type enum_description = {
  name : string;
  size : int;
  choices : (Loc.t * string * string * string) list;
  unknown_behaviour : unknown_behaviour;
  opts : enum_option list;
}

let mk_enum_desc n s c u o = {
 name = n; size = s;
 choices = c; unknown_behaviour = u; opts = o;
}


let mk_exception _loc enum = match enum with
  | {unknown_behaviour = Exception e} ->
    <:str_item< exception  $typ:ctyp_uid _loc e$  >>
  | _ -> <:str_item< >>

let mk_size_decl _loc enum =
  <:str_item< value $ <:binding< $pat:pat_lid _loc ("__" ^ enum.name ^ "_size")$ = $exp:exp_int _loc (string_of_int enum.size)$ >> $ >>


let mk_ctors _loc enum =
  let ctors = List.map (fun (_loc, _, n, _) -> ctyp_uid _loc n ) enum.choices in

  let suffix_choice = match enum.unknown_behaviour with
    | UnknownVal v -> [ <:ctyp< $ctyp_uid _loc v$ of int >> ]
    | _ -> []
  in

  let ctyp_ctors = ctors@suffix_choice in
  <:str_item< type $lid:enum.name$ = [ $list:ctyp_ctors$ ] >>


let mk_string_of_enum _loc enum =
  let mk_case (_loc, _, n, d) =
    let p, e = ( pat_uid _loc n, <:expr< $str:d$ >> ) in
    <:match_case< $p$ -> $e$ >>
  in
  let _cases = List.map mk_case enum.choices in
  let cases = match enum.unknown_behaviour with
    | UnknownVal v ->
      let p = <:patt<  $pat_uid _loc v$  $pat_lid _loc "i"$  >>
      and e = <:expr< $str:"Unknown " ^ enum.name ^ " ("$ ^ (string_of_int i) ^ $str:")"$ >>
      in _cases@[ <:match_case< $p$ -> $e$ >> ]
    | _ -> _cases
  in
  let body = <:expr< fun [ $list:cases$ ] >>
  and fun_name = pat_lid _loc ("string_of_" ^ enum.name) in
  let bindings = <:binding< $pat:fun_name$ = $exp:body$ >> in
  <:str_item< value $bindings$ >>


let mk_int_of_enum _loc enum =
  let mk_case (_loc, v, n, _) =
    let p, e = ( pat_uid _loc n, exp_int _loc v ) in
    <:match_case< $p$ -> $e$ >>
  in
  let _cases = List.map mk_case enum.choices in
  let cases = match enum.unknown_behaviour with
    | UnknownVal v ->
      let p = <:patt<  $pat_uid _loc v$ $pat_lid _loc "i"$ >>
      and e = exp_lid _loc "i"
      in _cases@[ <:match_case< $p$ -> $e$ >> ]
    | _ -> _cases
  in
  let body = <:expr< fun [ $list:cases$ ] >>
  and fun_name = pat_lid _loc ("int_of_" ^ enum.name) in
  let bindings = <:binding< $pat:fun_name$ = $exp:body$ >> in
  <:str_item< value $bindings$ >>


let mk_enum_of_int _loc enum =
  let mk_case (_loc, v, n, _) =
    let p, e = ( <:patt< $int:v$ >>, <:expr< $uid:n$ >> ) in
    <:match_case< $p$ -> $e$ >>
  in
  let _cases = List.map mk_case enum.choices in
  let cases = match enum.unknown_behaviour with
    | UnknownVal v ->
      let p = pat_lid _loc "i"
      and e = <:expr< $exp_uid _loc v$  $exp_lid _loc "i"$  >>
      in _cases@[ <:match_case< $p$ -> $e$ >> ]
    | Exception e ->
      let p = <:patt< _ >>
      and e = <:expr< raise $exp_uid _loc e$ >>
      in _cases@[ <:match_case< $p$ -> $e$ >> ]
  in
  let body = <:expr< fun [ $list:cases$ ] >>
  and fun_name = pat_lid _loc (enum.name ^ "_of_int") in
  let bindings = <:binding< $pat:fun_name$ = $exp:body$ >> in
  <:str_item< value $bindings$ >>


let mk_enum_of_string _loc enum =
  let mk_case (_loc, _, n, d) =
    let p, e = ( <:patt< $str:d$ >>, <:expr< $uid:n$ >> ) in
    <:match_case< $p$ -> $e$ >>
  in
  let _cases = List.map mk_case enum.choices in
  let cases =
    let p = pat_lid _loc "s"
    and e = <:expr< $ <:expr< $lid:(enum.name ^ "_of_int")$ >> $  ( $ <:expr< $lid:"int_of_string"$ >> $  $ <:expr< $lid:"s"$ >> $ )  >>
    in _cases@[ <:match_case< $p$ -> $e$ >> ]
  in
  let body = <:expr< fun [ $list:cases$ ] >>
  and fun_name = pat_lid _loc (enum.name ^ "_of_string") in
  let bindings = <:binding< $pat:fun_name$ = $exp:body$ >> in
  <:str_item< value $bindings$ >>


let mk_parse_dump_print_funs _loc enum =
  let ioe = exp_lid _loc ("int_of_" ^ enum.name)
  and eoi = exp_lid _loc (enum.name ^ "_of_int")
  and soe = exp_lid _loc ("string_of_" ^ enum.name) in

  let parse_fun =
    if enum.size mod 8 = 0 then begin
      let pf = <:expr< $exp_uid _loc "ParsingEngine"$.$exp_lid _loc ("parse_uint" ^ (string_of_int enum.size))$ >> in
      <:str_item< value $ <:binding< $pat:pat_lid _loc ("parse_" ^ enum.name)$ $pat:pat_lid _loc "input"$ =
	  $exp: <:expr< $eoi$ ($pf$ input) >> $ >> $ >>
    end else <:str_item< >>

  and lwt_parse_fun =
    if List.mem DoLwt enum.opts && enum.size mod 8 = 0 then begin
      let lpf = <:expr< $exp_uid _loc "LwtParsingEngine"$.$exp_lid _loc ("lwt_parse_uint" ^ (string_of_int enum.size))$ >> in
      <:str_item< value $ <:binding< $pat:pat_lid _loc ("lwt_parse_" ^ enum.name)$ $pat:pat_lid _loc "input"$ =
          $exp: <:expr< Lwt.bind ($lpf$ input) (fun x -> Lwt.return ( $ <:expr< $eoi$ x >> $ ) ) >> $ >> $ >>
    end else <:str_item< >>

  and dump_fun =
    if enum.size mod 8 = 0 then begin
      let df = <:expr< $exp_uid _loc "DumpingEngine"$.$exp_lid _loc ("dump_uint" ^ (string_of_int enum.size))$ >> in
      <:str_item< value $ <:binding< $pat:pat_lid _loc ("dump_" ^ enum.name)$ $pat:pat_lid _loc "v"$ =
	  $exp: <:expr< $df$ ($ioe$ v) >> $ >> $ >>
    end else <:str_item< >>

  and print_fun = <:str_item< value $ <:binding< $pat:pat_lid _loc ("print_" ^ enum.name)$ =
    $exp: <:expr< PrintingEngine.print_enum $soe$ $ioe$ >> $ >> $ >>

  in parse_fun, lwt_parse_fun, dump_fun, print_fun



EXTEND Gram
  GLOBAL: str_item;

  enum_elts: [[
    e1 = SELF; ";"; e2 = SELF -> e1 @ e2
  | v = INT; ","; constructor = ident; ","; display = STRING ->
    [(_loc, v, uid_of_ident _loc constructor, display)]
  | -> []
  ]];


  unknown_behaviour: [[
    "Exception"; x = ident -> Exception (uid_of_ident _loc x)
  | "UnknownVal"; x = ident -> UnknownVal (uid_of_ident _loc x)
  ]];

  options: [[
    o1 = SELF; ";"; o2 = SELF -> o1 @ o2
  | "lwt" -> [DoLwt]
  | -> []
  ]];

  str_item: [[
    "enum"; enum_name = ident;
    "("; sz = INT; ",";
         u_b = unknown_behaviour; ",";
	 "["; opts = options; "]";
    ")"; "="; "["; choices = enum_elts; "]" ->
      let enum_descr = mk_enum_desc (lid_of_ident _loc enum_name) (int_of_string sz) choices u_b opts in
      let si0 = mk_exception _loc enum_descr
      and si1 = mk_size_decl _loc enum_descr
      and si2 = mk_ctors _loc enum_descr
      and si3 = mk_string_of_enum _loc enum_descr
      and si4 = mk_int_of_enum _loc enum_descr
      and si5 = mk_enum_of_int _loc enum_descr
      and si6 = mk_enum_of_string _loc enum_descr
      and si7, si8, si9, si10 = mk_parse_dump_print_funs _loc enum_descr
      in
      <:str_item< $si0$; $si1$; $si2$; $si3$; $si4$; $si5$; $si6$; $si7$; $si8$; $si9$; $si10$ >>
  ]];
END
;;
