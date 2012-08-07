open Camlp4
open Camlp4.PreCast
open Syntax

type unknown_behaviour =
  | UnknownVal of string
  | Exception of string

type enum_options =
  | DoLwt


let ctor_name_of_ident _loc = function
  | <:ident< $uid:c$ >> -> c
  | _ -> Loc.raise _loc (Failure "constructor expected")


let pat_lid _loc name = <:patt< $lid:name$ >>
let pat_uid _loc name = <:patt< $uid:name$ >>
let exp_int _loc i = <:expr< $int:i$ >>
let exp_str _loc s = <:expr< $str:s$ >>
let exp_lid _loc name = <:expr< $lid:name$ >>
let exp_uid _loc name = <:expr< $uid:name$ >>

let mk_exception = function
  | _loc, Exception e ->
    let t = <:ctyp< $uid:e$ >> in
    <:str_item< exception  $typ:t$  >>
  | _loc, _ -> <:str_item< >>


let mk_ctors (_loc, name, enum, unknown) =
  let ctors = List.map (fun (_loc, _, n, _) -> <:ctyp< $uid:n$ >> ) enum in

  let suffix_choice = match unknown with
    | _loc, UnknownVal v -> [ <:ctyp<  $ <:ctyp< $uid:v$ >> $  of  int  >> ]
    | _ -> []
  in

  let ctyp_ctors = ctors@suffix_choice in
  let constructors = Ast.TySum (_loc, Ast.tyOr_of_list ctyp_ctors) in
  <:str_item< type $lid:name$ = $constructors$ >>


let mk_string_of_enum (_loc, name, enum, unknown) =
  let mk_case (_loc, _, n, d) =
    let p, e = ( pat_uid _loc n, <:expr< $str:d$ >> ) in
    <:match_case< $p$ -> $e$ >>
  in
  let _cases = List.map mk_case enum in
  let cases = match unknown with
    | _loc, UnknownVal v ->
      let p = <:patt<  $pat_uid _loc v$  $pat_lid _loc "i"$  >>
      and e = <:expr< $str:"Unknown " ^ name ^ " ("$ ^ (string_of_int i) ^ $str:")"$ >>
      in _cases@[ <:match_case< $p$ -> $e$ >> ]
    | _ -> _cases
  in
  let body = <:expr< fun [ $list:cases$ ] >>
  and fun_name = pat_lid _loc ("string_of_" ^ name) in
  let bindings = <:binding< $pat:fun_name$ = $exp:body$ >> in
  <:str_item< value $bindings$ >>


let mk_int_of_enum (_loc, name, enum, unknown) =
  let mk_case (_loc, v, n, _) =
    let p, e = ( pat_uid _loc n, exp_int _loc v ) in
    <:match_case< $p$ -> $e$ >>
  in
  let _cases = List.map mk_case enum in
  let cases = match unknown with
    | _loc, UnknownVal v ->
      let p = <:patt<  $pat_uid _loc v$ $pat_lid _loc "i"$ >>
      and e = exp_lid _loc "i"
      in _cases@[ <:match_case< $p$ -> $e$ >> ]
    | _ -> _cases
  in
  let body = <:expr< fun [ $list:cases$ ] >>
  and fun_name = pat_lid _loc ("int_of_" ^ name) in
  let bindings = <:binding< $pat:fun_name$ = $exp:body$ >> in
  <:str_item< value $bindings$ >>


let mk_enum_of_int (_loc, name, enum, unknown) =
  let mk_case (_loc, v, n, _) =
    let p, e = ( <:patt< $int:v$ >>, <:expr< $uid:n$ >> ) in
    <:match_case< $p$ -> $e$ >>
  in
  let _cases = List.map mk_case enum in
  let cases = match unknown with
    | _loc, UnknownVal v ->
      let p = pat_lid _loc "i"
      and e = <:expr< $exp_uid _loc v$  $exp_lid _loc "i"$  >>
      in _cases@[ <:match_case< $p$ -> $e$ >> ]
    | _loc, Exception e ->
      let p = <:patt< _ >>
      and e = <:expr< raise $exp_uid _loc e$ >>
      in _cases@[ <:match_case< $p$ -> $e$ >> ]
  in
  let body = <:expr< fun [ $list:cases$ ] >>
  and fun_name = pat_lid _loc (name ^ "_of_int") in
  let bindings = <:binding< $pat:fun_name$ = $exp:body$ >> in
  <:str_item< value $bindings$ >>


let mk_enum_of_string (_loc, name, enum, unknown) =
  let mk_case (_loc, _, n, d) =
    let p, e = ( <:patt< $str:d$ >>, <:expr< $uid:n$ >> ) in
    <:match_case< $p$ -> $e$ >>
  in
  let _cases = List.map mk_case enum in
  let cases =
    let p = pat_lid _loc "s"
    and e = <:expr< $ <:expr< $lid:(name ^ "_of_int")$ >> $  ( $ <:expr< $lid:"int_of_string"$ >> $  $ <:expr< $lid:"s"$ >> $ )  >>
    in _cases@[ <:match_case< $p$ -> $e$ >> ]
  in
  let body = <:expr< fun [ $list:cases$ ] >>
  and fun_name = pat_lid _loc (name ^ "_of_string") in
  let bindings = <:binding< $pat:fun_name$ = $exp:body$ >> in
  <:str_item< value $bindings$ >>


let mk_parse_dump_print_funs opts (_loc, name, _, _) =
  <:str_item< value $ <:binding< $pat:pat_lid _loc ("parse_" ^ name)$ $pat:pat_lid _loc "parse_int"$ $pat:pat_lid _loc "input"$ =
       $exp: <:expr< $exp_lid _loc (name ^ "_of_int")$ (parse_int input) >> $ >> $ >>,

  begin
    if List.mem DoLwt opts then
      <:str_item< value $ <:binding< $pat:pat_lid _loc ("lwt_parse_" ^ name)$ $pat:pat_lid _loc "lwt_parse_int"$ $pat:pat_lid _loc "input"$ =
           $exp: <:expr< Lwt.bind (lwt_parse_int input) (fun x -> Lwt.return ( $ <:expr< $exp_lid _loc (name ^ "_of_int")$ x >> $ ) ) >> $ >> $ >>
    else <:str_item< >>
  end,

  <:str_item< value $ <:binding< $pat:pat_lid _loc ("dump_" ^ name)$ $pat:pat_lid _loc "dump_int"$ $pat:pat_lid _loc "v"$ =
       $exp: <:expr< dump_int ( $exp_lid _loc ("int_of_" ^ name)$ v) >> $ >> $ >>,

  <:str_item< value $ <:binding< $pat:pat_lid _loc ("print_" ^ name)$ =
       $exp: <:expr< PrintingEngine.print_enum $exp_lid _loc ("string_of_" ^ name)$ $exp_lid _loc ("int_of_" ^ name)$ >> $ >> $ >>



EXTEND Gram
  GLOBAL: expr str_item;

  enum_elts: [[
    e1 = SELF; ";"; e2 = SELF -> e1 @ e2
  | v = INT; ","; constructor = ident; ","; display = STRING ->
    [(_loc, v, ctor_name_of_ident _loc constructor, display)]
  | -> []
  ]];


  unknown_behaviour: [[
    "Exception"; x = ident -> _loc, Exception (ctor_name_of_ident _loc x)
  | "UnknownVal"; x = ident -> _loc, UnknownVal (ctor_name_of_ident _loc x)
  ]];

  options: [[
    o1 = SELF; ";"; o2 = SELF -> o1 @ o2
  | "lwt" -> [DoLwt]
  | -> []
  ]];

  str_item: [[
    "enum"; enum_name = ident; "="; "["; choices = enum_elts; "]";
              ","; "["; u_b = unknown_behaviour; "]";
              ","; "["; opts = options; "]" ->
      let n = match enum_name with
        | <:ident< $lid:nn$ >> -> nn
        | _ -> Loc.raise _loc (Failure "type name expected")
      in
      let enum_descr = (_loc, n, choices, u_b) in
      let si0 = mk_exception u_b
      and si1 = mk_ctors enum_descr
      and si2 = mk_string_of_enum enum_descr
      and si3 = mk_int_of_enum enum_descr
      and si4 = mk_enum_of_int enum_descr
      and si5 = mk_enum_of_string enum_descr
      and si6, si7, si8, si9 = mk_parse_dump_print_funs opts enum_descr
      in
      <:str_item< $si0$; $si1$; $si2$; $si3$; $si4$; $si5$; $si6$; $si7$; $si8$; $si9$ >>
  ]];
END
;;
