(* ocamlc -pp "camlp4o pa_extend.cmo q_MLast.cmo" -I /usr/lib/ocaml/camlp4 -c preprocess_camlp4.ml *)

open Camlp4
open Camlp4.PreCast
open Syntax

type ctor_name = string
type choice = Loc.t * int * ctor_name * string

type type_name = string
type unknown_behaviour =
  | DefaultVal of string
  | UnknownVal of string
  | Exception of string
type enum = Loc.t * type_name * choice list * (Loc.t * unknown_behaviour)


let ctor_name_of_ident _loc = function
  | <:ident< $uid:c$ >> -> c
  | _ -> Loc.raise _loc (Failure "constructor expected")

let mk_ctors (_loc, name, enum, (loc_u, unknown)) =
  let ctors = List.map (fun (_, _, n, _) -> n) enum in

  let suffix_choice = match unknown with
    | DefaultVal v ->
      if not (List.mem v ctors)
      then Loc.raise loc_u (Failure "the default value is not specified")
      else []
    | UnknownVal v -> [v]
    | Exception _ -> []
  in

  let ctyp_of_uid c = <:ctyp< $uid:c$ >> in
  let ctyp_ctors = List.map ctyp_of_uid (ctors@suffix_choice) in
  let constructors = Ast.tyOr_of_list ctyp_ctors in
  <:str_item< type $lid:name$ = $constructors$ >>



EXTEND Gram
  GLOBAL: expr str_item;

  enum_elts: [ [
    e1 = SELF; ";"; e2 = SELF -> e1 @ e2
  | v = INT; ":"; constructor = ident; ":"; display = STRING ->
    [(_loc, int_of_string v, ctor_name_of_ident _loc constructor, display)]
  | -> []
  ] ];


  unknown_behaviour: [[
    "Exception"; x = ident -> _loc, Exception (ctor_name_of_ident _loc x)
  | "DefaultVal"; x = ident -> _loc, DefaultVal (ctor_name_of_ident _loc x)
  | "UnknownVal"; x = ident -> _loc, UnknownVal (ctor_name_of_ident _loc x)
  ]];

  str_item: [[
    "enum"; enum_name = ident; "="; "{"; choices = enum_elts; "}";
              ","; "<"; u_b = unknown_behaviour; ">" ->
      let n = match enum_name with
        | <:ident< $lid:nn$ >> -> nn
        | _ -> Loc.raise _loc (Failure "type name expected")
      in
      mk_ctors (_loc, n, choices, u_b)
    (* let si1 = <:str_item< type $typ:enum_name$ = unit >> in *)
    (* <:str_item< declare $si1$; $si1$; end >> ]]; *)
  ]];
END
;;
