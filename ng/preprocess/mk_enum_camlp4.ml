(* ocamlc -pp "camlp4o pa_extend.cmo q_MLast.cmo" -I /usr/lib/ocaml/camlp4 -c mk_enum_camlp4.ml *)

open Camlp4
open Camlp4.PreCast
open Syntax

type unknown_behaviour =
  | UnknownVal of string
  | Exception of string


let ctor_name_of_ident _loc = function
  | <:ident< $uid:c$ >> -> c
  | _ -> Loc.raise _loc (Failure "constructor expected")



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
    let p, e = ( <:patt< $uid:n$ >>, <:expr< $str:d$ >> ) in
    <:match_case< $p$ -> $e$ >>
  in
  let _cases = List.map mk_case enum in
  let cases = match unknown with
    | _loc, UnknownVal v ->
      let p = <:patt<  $ <:patt< $uid:v$ >> $  $ <:patt< $lid:"i"$ >> $  >>
      and e = <:expr< $str:"Unknown " ^ name ^ " ("$ ^ (string_of_int i) ^ $str:")"$ >>
      in _cases@[ <:match_case< $p$ -> $e$ >> ]
    | _ -> _cases
  in
  let body = <:expr< fun [ $list:cases$ ] >>
  and fun_name = <:patt< $lid:("string_of_" ^ name)$ >> in
  let bindings = <:binding< $pat:fun_name$ = $exp:body$ >> in
  <:str_item< value $bindings$ >>


let mk_int_of_enum (_loc, name, enum, unknown) =
  let mk_case (_loc, v, n, _) =
    let p, e = ( <:patt< $uid:n$ >>, <:expr< $int:v$ >> ) in
    <:match_case< $p$ -> $e$ >>
  in
  let _cases = List.map mk_case enum in
  let cases = match unknown with
    | _loc, UnknownVal v ->
      let p = <:patt<  $ <:patt< $uid:v$ >> $  $ <:patt< $lid:"i"$ >> $  >>
      and e = <:expr< $lid:"i"$ >>
      in _cases@[ <:match_case< $p$ -> $e$ >> ]
    | _ -> _cases
  in
  let body = <:expr< fun [ $list:cases$ ] >>
  and fun_name = <:patt< $lid:("int_of_" ^ name)$ >> in
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
      let p = <:patt< $lid:"i"$ >>
      and e = <:expr< $ <:expr< $uid:v$ >> $  $ <:expr< $lid:"i"$ >> $  >>
      in _cases@[ <:match_case< $p$ -> $e$ >> ]
    | _loc, Exception e ->
      let p = <:patt< _ >>
      and e = <:expr< $ <:expr< $lid:"raise"$ >> $  $ <:expr< $uid:e$ >> $  >>
      in _cases@[ <:match_case< $p$ -> $e$ >> ]
  in
  let body = <:expr< fun [ $list:cases$ ] >>
  and fun_name = <:patt< $lid:(name ^ "_of_int")$ >> in
  let bindings = <:binding< $pat:fun_name$ = $exp:body$ >> in
  <:str_item< value $bindings$ >>


let mk_enum_of_string (_loc, name, enum, unknown) =
  let mk_case (_loc, _, n, d) =
    let p, e = ( <:patt< $str:d$ >>, <:expr< $uid:n$ >> ) in
    <:match_case< $p$ -> $e$ >>
  in
  let _cases = List.map mk_case enum in
  let cases =
    let p = <:patt< $lid:"s"$ >>
    and e = <:expr< $ <:expr< $lid:(name ^ "_of_int")$ >> $  ( $ <:expr< $lid:"int_of_string"$ >> $  $ <:expr< $lid:"s"$ >> $ )  >>
    in _cases@[ <:match_case< $p$ -> $e$ >> ]
  in
  let body = <:expr< fun [ $list:cases$ ] >>
  and fun_name = <:patt< $lid:(name ^ "_of_string")$ >> in
  let bindings = <:binding< $pat:fun_name$ = $exp:body$ >> in
  <:str_item< value $bindings$ >>



(* let mk_parse_dump_print_funs do_lwt (name, _, _) = *)
(*   Printf.printf "let parse_%s parse_int input = %s_of_int (parse_int input)\n" name name; *)
(*   if do_lwt *)
(*   then Printf.printf "let lwt_parse_%s lwt_parse_int input = lwt_parse_int input >>= fun x -> return (%s_of_int x)\n" name name; *)
(*   Printf.printf "let dump_%s dump_int v = dump_int (int_of_%s v)\n" name name; *)
(*   Printf.printf "let print_%s = print_enum string_of_%s int_of_%s\n" name name name *)



EXTEND Gram
  GLOBAL: expr str_item;

  enum_elts: [ [
    e1 = SELF; ";"; e2 = SELF -> e1 @ e2
  | v = INT; ","; constructor = ident; ","; display = STRING ->
    [(_loc, v, ctor_name_of_ident _loc constructor, display)]
  | -> []
  ] ];


  unknown_behaviour: [[
    "Exception"; x = ident -> _loc, Exception (ctor_name_of_ident _loc x)
  | "UnknownVal"; x = ident -> _loc, UnknownVal (ctor_name_of_ident _loc x)
  ]];

  str_item: [[
    "enum"; enum_name = ident; "="; "["; choices = enum_elts; "]";
              ","; "["; u_b = unknown_behaviour; "]" ->
      let n = match enum_name with
        | <:ident< $lid:nn$ >> -> nn
        | _ -> Loc.raise _loc (Failure "type name expected")
      in
      let si0 = mk_exception u_b
      and si1 = mk_ctors (_loc, n, choices, u_b)
      and si2 = mk_string_of_enum (_loc, n, choices, u_b)
      and si3 = mk_int_of_enum (_loc, n, choices, u_b)
      and si4 = mk_enum_of_int (_loc, n, choices, u_b)
      and si5 = mk_enum_of_string (_loc, n, choices, u_b) in
      <:str_item< $si0$; $si1$; $si2$; $si3$; $si4$; $si5$ >>
  ]];
END
;;
