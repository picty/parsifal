open Camlp4.PreCast
open Camlp4.PreCast.Ast
open Syntax


(****************************)
(* Common trivial functions *)
(****************************)

let pop_option def = function
  | None -> def
  | Some x -> x


(***************************)
(* Common camlp4 functions *)
(***************************)

let uid_of_ident = function
  | IdUid (_, u) -> u
  | i -> Loc.raise (loc_of_ident i) (Failure "uppercase identifier expected")

let lid_of_ident = function
  | IdLid (_, l) -> l
  | i -> Loc.raise (loc_of_ident i) (Failure "lowercase identifier expected")

let lid_of_expr = function
  | <:expr< $lid:id$ >> -> id
  | e -> Loc.raise (loc_of_expr e) (Failure "lowercase identifier expected")

let exp_true _loc = <:expr< $uid:"True"$ >>
let exp_false _loc = <:expr< $uid:"False"$ >>
let exp_bool _loc b = if b then exp_true _loc else exp_false _loc

let rec exp_of_list _loc = function
  | [] -> <:expr< $uid:"[]"$ >>
  | e::r -> <:expr< $uid:"::"$ $e$ $exp_of_list _loc r$ >>


let list_of_com_expr =
  let rec _list_of_com_expr = function
    | ExNil _ -> []
    | ExCom (_, e1, e2) -> (_list_of_com_expr e1)@(_list_of_com_expr e2)
    | e -> [e]
  in function
  | ExTup (_loc, e) -> _list_of_com_expr e
  | e -> [e]

let list_of_sem_expr =
  let rec _list_of_sem_expr = function
    | ExNil _ -> []
    | ExSem (_, e1, e2) -> (_list_of_sem_expr e1)@(_list_of_sem_expr e2)
    | e -> [e]
  in function
  | ExSeq (_loc, e) -> _list_of_sem_expr e
  | e -> [e]


let exp_lid _loc n = <:expr< $lid:n$ >>

let exp_qname _loc m n = match m with
  | None -> <:expr< $lid:n$ >>
  | Some module_name -> <:expr< $uid:module_name$.$lid:n$ >>

let qname_ident = function
  | <:ident< $lid:n$ >> -> None, n
  | <:ident< $uid:module_name$.$lid:n$ >> -> Some module_name, n
  | i -> Loc.raise (loc_of_ident i) (Failure "invalid identifier")

let rec apply_exprs _loc e = function
  | [] -> e
  | a::r -> apply_exprs _loc <:expr< $e$ $a$ >> r


let rec expr_of_pat = function
  | PaApp (_loc, p1, p2) -> ExApp (_loc, expr_of_pat p1, expr_of_pat p2)
  | PaCom (_loc, p1, p2) -> ExCom (_loc, expr_of_pat p1, expr_of_pat p2)
  | PaTup (_loc, p) -> ExTup (_loc, expr_of_pat p)
  | PaAli (_, p, _) -> expr_of_pat p
  | PaId (_loc, i) -> ExId (_loc, i)
  | PaInt (_loc, i) -> ExInt (_loc, i)
  | p -> Loc.raise (loc_of_patt p) (Failure "pattern not supported for asn1_unions")


let mk_multiple_args_fun _loc fname argnames ?optargs:(optargnames=[]) body =
  let rec _mk_multiple_args_fun = function
    | [] -> body
    | arg::r -> <:expr< fun $ <:patt< $lid:arg$ >> $ -> $exp:_mk_multiple_args_fun r$ >>
  in
  let rec _mk_multiple_optargs_fun = function
    | [] -> _mk_multiple_args_fun argnames
    | (arg, e)::r -> <:expr< fun $pat:PaOlbi (_loc, arg, <:patt< $lid:arg$ >>, e)$ -> $exp:_mk_multiple_optargs_fun r$ >>
  in
  let b = <:binding< $pat: <:patt< $lid:fname$ >> $ = $exp:_mk_multiple_optargs_fun optargnames$ >>
  in <:str_item< value $b$ >>
