open Camlp4
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



(********************************************)
(* Types representing the new constructions *)
(********************************************)

(* Common *)

type parsifal_option =
  | DoLwt
  | LittleEndian
  | ExactParser
  | EnrichByDefault
  | ExhaustiveChoices
  | ParseParam of string list
  | DumpParam of string list


(* Enums *)
type enum_unknown_behaviour =
  | UnknownVal of string
  | Exception of string

type enum_description = {
  size : int;
  echoices : (Loc.t * string * string * string) list;
  unknown_behaviour : enum_unknown_behaviour;
}

  
(* PTypes *)
type field_len =
  | ExprLen of expr    (* size in bytes of the field *)
  | VarLen of string   (* name of the integer type used *)
  | Remaining

type ptype =
  | PT_Empty
  | PT_Int of string                        (* name of the integer type *)
  | PT_String of field_len * bool
  | PT_Array of expr * ptype
  | PT_List of field_len * ptype
  | PT_Container of field_len * ptype  (* the string corresponds to the integer type for the field length *)
  | PT_Custom of (string option) * string * expr list * expr list (* the expr lists are the args to give to parse / dump *)
  | PT_CustomContainer of (string option) * string * expr list * expr list * ptype


(* Records *)
type field_attribute = Optional | ParseCheckpoint | ParseField
type struct_description = (Loc.t * string * ptype * field_attribute option) list


(* Unions *)
(* ASN1 Unions *)
type union_description = {
  uchoices : (Loc.t * patt * string * ptype) list;   (* loc, discriminating value, constructor, subtype *)
  unparsed_constr : string;
  unparsed_type : ptype;
}


(* Aliases *)
type alias_description = ptype


(* ASN1 Aliases *)
(* TODO: Add options [keep header/keep raw string] *)
type asn1_alias_header =
  | Universal of string
  | Header of string * int

type asn1_alias_description = {
  aaheader : asn1_alias_header * bool;
  aalist : bool;
  aatype : ptype;
}


(* Constructions *)
type construction_description =
  | Enum of enum_description
  | Struct of struct_description
  | Union of union_description
  | ASN1Union of union_description
  | Alias of alias_description
  | ASN1Alias of asn1_alias_description

type parsifal_construction = {
  name : string;
  options : parsifal_option list;
  construction : construction_description;
  parse_params : string list;
  dump_params : string list
}



(***************************)
(* Input AST interpreter   *)
(*   AST -> ParsifalSyntax *)
(***************************)

(* Options *)

let opts_of_seq_expr expr =
  let opt_of_exp e =
    let _loc = loc_of_expr e in
    match e with
    | <:expr< $lid:"with_lwt"$ >>   -> [_loc, DoLwt]
    | <:expr< $lid:"with_exact"$ >> -> [_loc, ExactParser]
    | <:expr< $lid:"top"$ >>        -> [_loc, DoLwt; _loc, ExactParser]
    | <:expr< $lid:"enrich"$ >>     -> [_loc, EnrichByDefault]
    | <:expr< $lid:"exhaustive"$ >> -> [_loc, ExhaustiveChoices]
    | <:expr< $lid:"parse_param"$ $e$ >>
    | <:expr< $lid:"param"$ $e$ >>  -> [_loc, ParseParam (List.map lid_of_expr (list_of_com_expr e))]
    | <:expr< $lid:"dump_param"$ $e$ >>  -> [_loc, DumpParam (List.map lid_of_expr (list_of_com_expr e))]
    | <:expr< $lid:"both_param"$ $e$ >>  ->
      [_loc, ParseParam (List.map lid_of_expr (list_of_com_expr e));
       _loc, DumpParam (List.map lid_of_expr (list_of_com_expr e))]
    | <:expr< $lid:"little_endian"$ >>   -> [_loc, LittleEndian]
    | _ -> Loc.raise (loc_of_expr e) (Failure "unknown option")
  in
  List.concat (List.map opt_of_exp (list_of_sem_expr expr))


(* Enum choices *)

let rec choices_of_match_cases = function
  | McNil _ -> []
  | McOr (_, m1, m2) ->
    (choices_of_match_cases m1)@(choices_of_match_cases m2)
  | McArr (_loc, <:patt< $int:i$ >>, <:expr< >>,
	   ExTup (_, ExCom (_, <:expr< $uid:c$ >>, <:expr< $str:s$ >> ))) ->
    [_loc, i, c, s]
  | McArr (_loc, <:patt< $int:i$ >>, <:expr< >>, <:expr< $uid:c$ >> ) ->
    [_loc, i, c, c]
  | mc -> Loc.raise (loc_of_match_case mc) (Failure "Invalid choice for an enum")


(* PTypes *)

type decorator_type = (expr option) * (expr option)

let expr_list_of_decorator = function
  | None -> []
  | Some e -> list_of_sem_expr e

let ptype_of_ident name decorator subtype =
  match name, decorator, subtype with
    | <:ident< $lid:("uint8"|"uint16"|"uint24"|"uint32" as int_t)$ >>, (None, None), None -> PT_Int int_t

    | <:ident< $lid:"list"$ >>, (None, None), Some t ->
      PT_List (Remaining, t)
    | <:ident< $lid:"list"$ >>, (None, Some e), Some t ->
      PT_List (ExprLen e, t)
    | <:ident< $lid:"list"$ >>, (Some <:expr< $lid:("uint8"|"uint16"|"uint24"|"uint32" as int_t)$ >>, None), Some t ->
      PT_List (VarLen int_t, t)
    | <:ident< $lid:"list"$ >> as i,   _, _ ->
      Loc.raise (loc_of_ident i) (Failure "invalid list type")

    | <:ident< $lid:"array"$ >>, (None, Some e), Some t ->
      PT_Array (e, t)

    | <:ident< $lid:"container"$ >>, (None, Some e), Some t ->
      PT_Container (ExprLen e, t)
    | <:ident< $lid:"container"$ >>, (Some <:expr< $lid:("uint8"|"uint16"|"uint24"|"uint32" as int_t)$ >>, None), Some t ->
      PT_Container (VarLen int_t, t)
    | <:ident< $lid:"container"$ >> as i, _, _ ->
      Loc.raise (loc_of_ident i) (Failure "invalid container type")

    | <:ident< $lid:"string"$ >>,    (None, None), None-> PT_String (Remaining, false)
    | <:ident< $lid:"binstring"$ >>, (None, None), None -> PT_String (Remaining, true)
    | <:ident< $lid:"string"$ >>,    (None, Some e), None ->
      PT_String (ExprLen e, false)
    | <:ident< $lid:"binstring"$ >>, (None, Some e), None ->
      PT_String (ExprLen e, true)
    | <:ident< $lid:"string"$ >>,    (Some <:expr< $lid:("uint8"|"uint16"|"uint24"|"uint32" as int_t)$ >>, None), None ->
      PT_String (VarLen int_t, false)
    | <:ident< $lid:"binstring"$ >>, (Some <:expr< $lid:("uint8"|"uint16"|"uint24"|"uint32" as int_t)$ >>, None), None ->
      PT_String (VarLen int_t, true)
    | <:ident< $lid:("string" | "binstring")$ >> as i, _, _ ->
      Loc.raise (loc_of_ident i) (Failure "invalid string type")

    | custom_identifier, (dec1, dec2), None ->
      let module_name, name = qname_ident (custom_identifier)
      and e1 = expr_list_of_decorator dec1
      and e2 = expr_list_of_decorator dec2 in
      PT_Custom (module_name, name, e1@e2, e1)

    | custom_identifier, (dec1, dec2), Some t ->
      let module_name, name = qname_ident (custom_identifier)
      and e1 = expr_list_of_decorator dec1
      and e2 = expr_list_of_decorator dec2 in
      PT_CustomContainer (module_name, name, e1@e2, e1, t)


(* ASN1 Aliases *)

let asn1_alias_of_ident name hdr =
  match lid_of_ident name, hdr with
  | "primitive", Some h -> (h, false), false
  | "constructed", Some h -> (h, true), false
  | "constructed_of", Some h -> (h, true), true
  | ("sequence_of"|"seq_of"), None -> (Universal "T_Sequence", true), true
  | "set_of", None -> (Universal "T_Set", true), true
  | "sequence", None -> (Universal "T_Sequence", true), false
  | "set", None -> (Universal "T_Set", true), false
  | _ -> Loc.raise (loc_of_ident name) (Failure "invalid identifier for an ASN.1 alias")




(*****************************)
(* OCaml definitions         *)
(*   ParsifalSyntax -> OCaml *)
(*****************************)

(* Common useful functions *)

(* TODO: if two lines are inconsistent, there is no warning...      *)
(*       for enums, we only need to check the 4th field is the same *)
(*       for unions it is more complicated                          *)

let keep_unique_cons constructors =
  let rec _keep_unique_cons names accu = function
  | [] -> List.rev accu
  | ((_, _, n, _) as c)::r  ->
    if List.mem n names
    then _keep_unique_cons names accu r
    else _keep_unique_cons (n::names) (c::accu) r
  in _keep_unique_cons [] [] constructors

let rec ocaml_type_of_ptype _loc = function
  | PT_Empty -> Loc.raise _loc (Failure "Empty types should never be concretized")
  | PT_Int _ -> <:ctyp< $lid:"int"$ >>
  | PT_String _ -> <:ctyp< $lid:"string"$ >>
  | PT_List (_, subtype) -> <:ctyp< list $ocaml_type_of_ptype _loc subtype$ >>
  | PT_Array (_, subtype) -> <:ctyp< array $ocaml_type_of_ptype _loc subtype$ >>
  | PT_Container (_, subtype)
  | PT_CustomContainer (_, _, _, _, subtype) -> ocaml_type_of_ptype _loc subtype
  | PT_Custom (None, n, _, _) -> <:ctyp< $lid:n$ >>
  | PT_Custom (Some m, n, _, _) -> <:ctyp< $uid:m$.$lid:n$ >>

let ocaml_type_of_field_type _loc t opt =
  let real_t = ocaml_type_of_ptype _loc t in
  if opt = Some Optional then <:ctyp< option $real_t$ >> else real_t

let keep_built_fields (_, _, _, o) = o <> (Some ParseCheckpoint)
let keep_real_fields (_, _, _, o) =
  (o <> (Some ParseCheckpoint)) && (o <> (Some ParseField))


(* Specific declarations for enums/unions *)

let mk_decls _loc c =
  match c.construction with
  | Enum {unknown_behaviour = Exception e} ->
    [ <:str_item< exception  $typ:<:ctyp< $uid:e$ >>$  >> ]
  | Union union | ASN1Union union ->
    let enrich_bool = List.mem EnrichByDefault c.options in
    let bool_name = <:patt< $lid:"enrich_" ^ c.name$ >>
    and bool_val = <:expr< ref $exp_bool _loc enrich_bool$ >> in
    [ <:str_item< value $ <:binding< $pat:bool_name$ = $exp:bool_val$ >> $ >> ]
  | _ -> []


(* mk_type function *)

let mk_type _loc c =
  let type_body = match c.construction with
    | Enum enum ->
      let ctors = List.map (fun (_loc, _, n, _) -> <:ctyp< $uid:n$ >>) (keep_unique_cons enum.echoices) in
      let suffix_choice = match enum.unknown_behaviour with
	| UnknownVal v -> [ <:ctyp< $ <:ctyp< $uid:v$ >> $ of int >> ]
	| _ -> []
      in
      <:ctyp< [ $list:ctors@suffix_choice$ ] >>

    | Struct fields ->
      let mk_line (_loc, n, t, opt) = <:ctyp< $lid:n$ : $ocaml_type_of_field_type _loc t opt$ >> in
      let ctyp_fields = List.map mk_line (List.filter keep_built_fields fields) in
      <:ctyp< { $list:ctyp_fields$ } >>

    | Union union | ASN1Union union ->
      let rec mk_ctors = function
	| [] ->
	  [ <:ctyp< $ <:ctyp< $uid:union.unparsed_constr$ >> $ of
	      $ocaml_type_of_ptype _loc union.unparsed_type$ >> ]
	| (_loc, _, n, PT_Empty)::r ->
	  (<:ctyp< $uid:n$ >>)::(mk_ctors r)
	| (_loc, _, n, t)::r ->
	  ( <:ctyp< $ <:ctyp< $uid:n$ >> $ of
          $ocaml_type_of_ptype _loc t$ >> )::(mk_ctors r)
      in
      <:ctyp< [ $list:mk_ctors (keep_unique_cons union.uchoices)$ ] >>

    | Alias atype -> ocaml_type_of_ptype _loc atype

    | ASN1Alias alias ->
      if alias.aalist
      then <:ctyp< list $ocaml_type_of_ptype _loc alias.aatype$ >>
      else ocaml_type_of_ptype _loc alias.aatype

  in [ <:str_item< type $lid:c.name$ = $type_body$ >> ] 


(* Enum specific functions *)

let mk_specific_funs _loc c =
  match c.construction with
  | Enum enum ->
    let mk_pm_fun (fname, cases) =
      let mk_case (p, e) = <:match_case< $p$ -> $e$ >> in
      let cases = List.map mk_case cases in
      let body = <:expr< fun [ $list:cases$ ] >>
      and fun_name = <:patt< $lid:fname$ >> in
      let bindings = <:binding< $pat:fun_name$ = $exp:body$ >> in
      <:str_item< value $bindings$ >>
    in

    let mk_string_of_enum =
      let mk_case (_loc, _, n, d) = <:patt< $uid:n$ >>, <:expr< $str:d$ >> in
      let _cases = List.map mk_case (keep_unique_cons enum.echoices) in
      let cases = match enum.unknown_behaviour with
	| UnknownVal v ->
	  let p = <:patt< $ <:patt< $uid:v$ >> $ $ <:patt< $lid:"i"$ >> $ >>
	  and e = <:expr< $str:"Unknown " ^ c.name ^ " ("$ ^ (string_of_int i) ^ $str:")"$ >>
	  in _cases@[p, e]
	| _ -> _cases
      and fname = "string_of_" ^ c.name in
      (fname, cases)

    and mk_int_of_enum =
      let mk_case (_loc, v, n, _) = <:patt< $uid:n$ >>, <:expr< $int:v$ >> in
      let _cases = List.map mk_case (keep_unique_cons enum.echoices) in
      let cases = match enum.unknown_behaviour with
	| UnknownVal v ->
	  let p = <:patt< $ <:patt< $uid:v$ >> $ $ <:patt< $lid:"i"$ >> $ >>
	  and e = <:expr< $lid:"i"$ >>
	  in _cases@[p, e]
	| _ -> _cases
      and fname = "int_of_" ^ c.name in
      (fname, cases)

    and mk_enum_of_int =
      let mk_case (_loc, v, n, _) = <:patt< $int:v$ >>, <:expr< $uid:n$ >> in
      let _cases = List.map mk_case enum.echoices in
      let last_p, last_e = match enum.unknown_behaviour with
	| UnknownVal v ->
	  <:patt< $lid:"i"$ >>,
	  <:expr< $ <:expr< $uid:v$ >> $ $ <:expr< $lid:"i"$ >> $ >>
	| Exception e ->
	  <:patt< _ >>, <:expr< raise $uid:e$ >>
      in
      let cases = _cases@[last_p, last_e]
      and fname = c.name ^ "_of_int" in
      (fname, cases)

    and mk_enum_of_string =
      let mk_case (_loc, _, n, d) = <:patt< $str:d$ >>, <:expr< $uid:n$ >> in
      let _cases = List.map mk_case (keep_unique_cons enum.echoices) in
      let last_p = <:patt< $lid:"s"$ >>
      and eoi = <:expr< $lid:c.name ^ "_of_int"$ >> in
      let last_e = <:expr< $eoi$  (int_of_string s) >> in
      let cases = _cases@[last_p, last_e]
      and fname = c.name ^ "_of_string" in
      (fname, cases)
    in

    let fns = [mk_int_of_enum; mk_string_of_enum;
	       mk_enum_of_int; mk_enum_of_string] in
    List.map mk_pm_fun fns
  | _ -> []



(*****************************)
(* OCaml functions           *)
(*   ParsifalSyntax -> OCaml *)
(*****************************)

(* Common *)

type function_type = Parse | LwtParse | Dump | Print

let rec fun_of_ptype ftype _loc name t =
  let prefix = match ftype with
    | Parse -> "parse_" | LwtParse -> "lwt_parse_"
    | Dump -> "dump_"   | Print -> "print_"
  in
  let mkf fname = exp_qname _loc (Some "Parsifal") (prefix ^ fname) in
  match t, ftype with
  (* Trivial ptypes *)
    | PT_Empty, _ -> mkf "empty"
    | PT_Int int_t, _ -> mkf int_t

  (* String *)
    | PT_String (VarLen int_t, _), Dump ->
      <:expr< $mkf "varlen_string"$ $mkf int_t$ >>
    | PT_String (_, _), Dump -> mkf "string"

    | PT_String (_, true), Print -> mkf "binstring"
    | PT_String (_, false), Print -> mkf "printablestring"

    | PT_String (ExprLen e, _), (Parse|LwtParse) ->
      <:expr< $mkf "string"$ $e$ >>
    | PT_String (VarLen int_t, _), (Parse|LwtParse) ->
      <:expr< $mkf "varlen_string"$ $str:name$ $mkf int_t$ >>
    | PT_String (Remaining, _), (Parse|LwtParse) ->
      mkf "rem_string"

  (* List *)
    | PT_List (VarLen int_t, subtype), Dump ->
      <:expr< $mkf "varlen_list"$ $mkf int_t$
	      $fun_of_ptype ftype _loc name subtype$ >>
    | PT_List (_, subtype), (Dump|Print) ->
      <:expr< $mkf "list"$ $fun_of_ptype ftype _loc name subtype$ >>

    | PT_List (ExprLen e, subtype), (Parse|LwtParse) ->
      <:expr< $mkf "list"$ $e$
              $fun_of_ptype ftype _loc name subtype$ >>
    | PT_List (Remaining, subtype), (Parse|LwtParse) ->
      <:expr< $mkf "rem_list"$
              $fun_of_ptype ftype _loc name subtype$ >>
    (* For VarLen lists, the items are parsed in string_inputs *)
    | PT_List (VarLen int_t, subtype), (Parse|LwtParse) ->
      <:expr< $mkf "varlen_list"$ $str:name$ $mkf int_t$
              $fun_of_ptype Parse _loc name subtype$ >>

  (* Array *)
    | PT_Array (_, subtype), (Dump|Print) ->
      <:expr< $mkf "array"$ $fun_of_ptype ftype _loc name subtype$ >>

    | PT_Array (e, subtype), (Parse|LwtParse) ->
      <:expr< $mkf "array"$ $e$
              $fun_of_ptype ftype _loc name subtype$ >>

  (* Container *)
    | PT_Container (VarLen int_t, subtype), Dump ->
      <:expr< $mkf "container"$ $mkf int_t$
	      $fun_of_ptype ftype _loc name subtype$ >>

    (* For containers, the subtype is always parsed with strings *)
    | PT_Container (ExprLen e, subtype), (Parse|LwtParse) ->
      <:expr< $mkf "container"$ $str:name$ $e$
              $fun_of_ptype Parse _loc name subtype$ >>
    | PT_Container (VarLen int_t, subtype), (Parse|LwtParse) ->
      <:expr< $mkf "varlen_container"$ $str:name$ $mkf int_t$
              $fun_of_ptype Parse _loc name subtype$ >>

    (* General case *)
    | PT_Container (_, subtype), _ ->
      fun_of_ptype ftype _loc name subtype

  (* Custom *)
    | PT_Custom (m, n, e, _), (Parse|LwtParse) ->
      apply_exprs _loc (exp_qname _loc m (prefix ^ n)) e
    | PT_Custom (m, n, _, e), Dump ->
      apply_exprs _loc (exp_qname _loc m (prefix ^ n)) e
    | PT_Custom (m, n, _, _), Print -> exp_qname _loc m (prefix ^ n)
      
  (* Custom Container *)
  (* For containers, the subtype is always parsed with strings *)
    | PT_CustomContainer (m, n, e, _, subtype), (Parse|LwtParse) ->
      apply_exprs _loc (exp_qname _loc m (prefix ^ n))
	(e@[fun_of_ptype Parse _loc name subtype])
    | PT_CustomContainer (m, n, _, e, subtype), Dump ->
      apply_exprs _loc (exp_qname _loc m (prefix ^ n))
	(e@[fun_of_ptype Dump _loc name subtype])
    | PT_CustomContainer (_, _, _, _, subtype), Print ->
      fun_of_ptype ftype _loc name subtype


let mk_exact_parse_fun _loc c =
  if List.mem ExactParser c.options then begin
    let partial_params = List.map (fun p -> <:expr< $lid:p$ >>) c.parse_params
    and params = c.parse_params@["input"] in
    let parse_fun = apply_exprs _loc (exp_qname _loc None ("parse_" ^ c.name)) partial_params in
    let body = <:expr< Parsifal.exact_parse $parse_fun$ input >> in
    [ mk_multiple_args_fun _loc ("exact_parse_" ^ c.name) params body ]
  end else []


(* Enum *)

(* let mk_enum_parse_fun _loc enum =  *)
(*   if enum.size mod 8 = 0 then begin *)
(*     let le = (if List.mem LittleEndian enum.options then "le" else "") in *)
(*     let fname = "parse_" ^ enum.name *)
(*     and parse_int_fun = exp_qname _loc (Some "Parsifal") ("parse_uint" ^ (string_of_int enum.size) ^ le) *)
(*     and eoi = <:expr< $lid:enum.ename ^ "_of_int"$ >> in *)
(*     let body = <:expr< $eoi$ ($parse_int_fun$ input) >> in *)
(*     [ mk_multiple_args_fun _loc fname ["input"] body ] *)
(*   end else [] *)

(* let mk_enum_lwt_parse_fun _loc enum = *)
(*   if enum.edo_lwt && enum.size mod 8 = 0 then begin *)
(*     let le = (if enum.le then "le" else "") in *)
(*     let fname = "lwt_parse_" ^ enum.ename *)
(*     and lwt_parse_int_fun = exp_qname _loc (Some "Parsifal") ("lwt_parse_uint" ^ (string_of_int enum.size) ^ le) *)
(*     and eoi = <:expr< $lid:enum.ename ^ "_of_int"$ >> in *)
(*     let body = <:expr< Lwt.bind ($lwt_parse_int_fun$ input) (Lwt.wrap1 $eoi$) >> in *)
(*     [ mk_multiple_args_fun _loc fname ["input"] body ] *)
(*   end else [] *)

(* let mk_enum_dump_fun _loc enum = *)
(*   if enum.size mod 8 = 0 then begin *)
(*     let le = (if enum.le then "le" else "") in *)
(*     let fname = "dump_" ^ enum.ename *)
(*     and dump_int_fun = exp_qname _loc (Some "Parsifal") ("dump_uint" ^ (string_of_int enum.size) ^ le) *)
(*     and ioe = <:expr< $lid:"int_of_" ^ enum.ename$ >> in *)
(*     let body = <:expr< $dump_int_fun$ ($ioe$ $lid:enum.ename$) >> in *)
(*     [ mk_multiple_args_fun _loc fname [enum.ename] body ] *)
(*   end else [] *)

(* let mk_enum_print_fun _loc enum = *)
(*   let fname = "print_" ^ enum.ename *)
(*   and print_fun = exp_qname _loc (Some "Parsifal") ("print_enum") *)
(*   and ioe = <:expr< $lid:"int_of_" ^ enum.ename$ >> *)
(*   and soe = <:expr< $lid:"string_of_" ^ enum.ename$ >> in *)
(*   let body = <:expr< $print_fun$ $soe$ $ioe$ $int:string_of_int (enum.size / 4)$ *)
(*               ~indent:indent ~name:name $lid:enum.ename$ >> *)
(*   and optargs = ["indent", <:expr< $str:""$ >>; "name", <:expr< $str:enum.ename$ >>] in *)
(*   [ mk_multiple_args_fun _loc fname [enum.ename] ~optargs:optargs body ] *)


(* (\* Struct *\) *)

(* let mk_struct_parse_fun _loc fields = *)
(*   let rec mk_body = function *)
(*     | [] -> *)
(*       let single_assign (_loc, n, _, _) = <:rec_binding< $lid:n$ = $exp: <:expr< $lid:n$ >> $ >> in *)
(*       let assignments = List.map single_assign (List.filter keep_built_fields fields) in *)
(*       <:expr< { $list:assignments$ } >> *)
(*     | (_loc, n, t, attribute)::r -> *)
(*       let tmp = mk_body r *)
(*       and f = fun_of_ptype Parse _loc n t in *)
(*       if attribute = Some Optional *)
(*       then <:expr< let $lid:n$ = Parsifal.try_parse $f$ input in $tmp$ >> *)
(*       else <:expr< let $lid:n$ = $f$ input in $tmp$ >> *)
(*   in *)
(*   let body = mk_body record.fields in *)
(*   let params = record.rparse_params@["input"] in *)
(*   [ mk_multiple_args_fun _loc ("parse_" ^ record.rname) params body ] *)

(* let mk_struct_lwt_parse_fun _loc record = *)
(*   let rec mk_body = function *)
(*     | [] -> *)
(*       let single_assign (_loc, n, _, _) = <:rec_binding< $lid:n$ = $exp: <:expr< $lid:n$ >> $ >> in *)
(*       let assignments = List.map single_assign (List.filter keep_built_fields record.fields) in *)
(*       <:expr< Lwt.return { $list:assignments$ } >> *)
(*     | (_loc, n, t, attribute)::r -> *)
(*       let tmp = mk_body r *)
(*       and f = fun_of_ptype LwtParse _loc n t in *)
(*       if attribute = Some Optional *)
(*       then <:expr< Lwt.bind (LwtParsingEngine.try_lwt_parse $f$ input) (fun $lid:n$ -> $tmp$ ) >> *)
(*       else <:expr< Lwt.bind ($f$ input) (fun $lid:n$ -> $tmp$ ) >> *)
(*   in *)
(*   if record.rdo_lwt then begin *)
(*     let body = mk_body record.fields in *)
(*     let params = record.rparse_params@["input"] in *)
(*     [ mk_multiple_args_fun _loc ("lwt_parse_" ^ record.rname) params body ] *)
(*   end else [] *)

(* let mk_struct_dump_fun _loc record = *)
(*   let dump_one_field (_loc, n, t, attribute) = *)
(*     let f = fun_of_ptype Dump _loc n t in *)
(*     if attribute = Some Optional *)
(*     then <:expr< Parsifal.try_dump $f$ $lid:record.rname$.$lid:n$ >> *)
(*     else <:expr< $f$ $lid:record.rname$.$lid:n$ >> *)
(*   in *)
(*   let fields_dumped_expr = exp_of_list _loc (List.map dump_one_field (List.filter keep_real_fields record.fields)) in *)
(*   let body = *)
(*     <:expr< let $lid:"fields_dumped"$ = $fields_dumped_expr$ in *)
(* 	    String.concat "" fields_dumped >> *)
(*   in *)
(*   let params = record.rdump_params@[record.rname] in *)
(*   [ mk_multiple_args_fun _loc ("dump_" ^ record.rname) params body ] *)

(* let mk_struct_print_fun _loc record = *)
(*   let print_one_field (_loc, n, t, attribute) = *)
(*     let f = fun_of_ptype Print _loc n t in *)
(*     if attribute = Some Optional *)
(*     then <:expr< Parsifal.try_print $f$ ~indent:new_indent ~name:$str:n$ $lid:record.rname$.$lid:n$ >> *)
(*     else <:expr< $f$ ~indent:new_indent ~name:$str:n$ $lid:record.rname$.$lid:n$ >> *)
(*   in *)
(*   let fields_printed_expr = exp_of_list _loc (List.map print_one_field (List.filter keep_real_fields record.fields)) in *)
(*   let body = *)
(*     <:expr< let new_indent = indent ^ "  " in *)
(* 	    let $lid:"fields_printed"$ = $fields_printed_expr$ in *)
(* 	    indent ^ name ^ " {\\n" ^ *)
(* 	    (String.concat "" fields_printed) ^ *)
(* 	    indent ^ "}\\n" >> *)
(*   in *)
(*   [ mk_multiple_args_fun _loc ("print_" ^ record.rname) [record.rname] *)
(*       ~optargs:(["indent", <:expr< $str:""$ >>; "name", <:expr< $str:record.rname$ >> ]) body ] *)


(* (\* Union *\) *)

(* let mk_union_parse_fun _loc union = *)
(*   let mk_case = function *)
(*     | (_loc, p, c, PT_Empty) -> *)
(*       <:match_case< $p$ -> $ <:expr< $uid:c$ >> $ >> *)
(*     | (_loc, p, c, t) -> *)
(*       let parse_fun = fun_of_ptype Parse _loc union.uname t in *)
(*       <:match_case< $p$ -> $ <:expr< $uid:c$ >> $ ($parse_fun$ input) >> *)
(*   and mk_unparsed = *)
(*     let parse_fun = fun_of_ptype Parse _loc union.uname union.unparsed_type in *)
(*     <:expr< $uid:union.unparsed_constr$ ($parse_fun$ input) >> *)
(*   in *)
(*   let parsed_cases = List.map mk_case union.uchoices *)
(*   and last_case = <:match_case< _ -> $mk_unparsed$ >> in *)
(*   let cases = if union.uexhaustive then parsed_cases else parsed_cases@[last_case] in *)
(*   let body = *)
(*     <:expr< if Parsifal.should_enrich $lid:"enrich_" ^ union.uname$ input.Parsifal.enrich *)
(*       then match discriminator with [ $list:cases$ ] *)
(*       else $mk_unparsed$ >> *)
(*   in *)
(*   let params = union.uparse_params@["input"] in *)
(*   [ mk_multiple_args_fun _loc ("parse_" ^ union.uname) params body ] *)

(* let mk_union_lwt_parse_fun _loc union = *)
(*   let mk_case = function *)
(*     | (_loc, p, c, PT_Empty) -> *)
(*       <:match_case< $p$ -> Lwt.return $ <:expr< $uid:c$ >> $ >> *)
(*     | (_loc, p, c, t) -> *)
(*       let parse_fun = fun_of_ptype LwtParse _loc union.uname t in *)
(*       <:match_case< $p$ -> Lwt.bind ($parse_fun$ input) (fun v -> Lwt.return ($ <:expr< $uid:c$ >> $ v)) >> *)
(*   and mk_unparsed = *)
(*     let parse_fun = fun_of_ptype LwtParse _loc union.uname union.unparsed_type in *)
(*     <:expr< Lwt.bind ($parse_fun$ input) (fun v -> Lwt.return ($ <:expr< $uid:union.unparsed_constr$ >> $ v)) >> *)
(*   in *)
(*   if union.udo_lwt then begin *)
(*     let parsed_cases = List.map mk_case union.uchoices *)
(*     and last_case = <:match_case< _ -> $mk_unparsed$ >> in *)
(*     let cases = if union.uexhaustive then parsed_cases else parsed_cases@[last_case] in *)
(*     let body = *)
(*       <:expr< if Parsifal.should_enrich $lid:"enrich_" ^ union.uname$ input.Parsifal.lwt_enrich *)
(* 	then match discriminator with [ $list:cases$ ] *)
(* 	else $mk_unparsed$ >> *)
(*     in *)
(*     let params = union.uparse_params@["input"] in *)
(*     [ mk_multiple_args_fun _loc ("lwt_parse_" ^ union.uname) params body ] *)
(*   end else [] *)

(* let mk_union_dump_fun _loc union = *)
(*   let mk_case = function *)
(*     | _loc, _, c, PT_Empty -> *)
(*       <:match_case< $ <:patt< $uid:c$ >> $ -> "" >> *)
(*     | _loc, n, c, t -> *)
(*       <:match_case< ( $ <:patt< $uid:c$ >> $  $ <:patt< $lid:"x"$ >> $ ) -> *)
(*                     $ <:expr< $fun_of_ptype Dump _loc union.uname t$ x >> $ >> *)
(*   in *)
(*   let last_case = *)
(*     <:match_case< ( $ <:patt< $uid:union.unparsed_constr$ >> $  $ <:patt< $lid:"x"$ >> $ ) -> *)
(*                   $ <:expr< $fun_of_ptype Dump _loc union.uname union.unparsed_type$ x >> $ >> *)
(*   in *)
(*   let cases = (List.map mk_case (keep_unique_cons union.uchoices))@[last_case] in *)
(*   let body = <:expr< fun [ $list:cases$ ] >> in *)
(*   [ mk_multiple_args_fun _loc ("dump_" ^ union.uname) union.udump_params body ] *)

(* let mk_union_print_fun _loc union = *)
(*   let mk_case = function *)
(*     | _loc, _, c, PT_Empty -> *)
(*       <:match_case< $ <:patt< $uid:c$ >> $ -> *)
(*       Parsifal.print_binstring ~indent:indent ~name:name "" >> *)
(*     | _loc, n, c, t -> *)
(*       <:match_case< ( $ <:patt< $uid:c$ >> $  $ <:patt< $lid:"x"$ >> $ ) -> *)
(*                     $ <:expr< $fun_of_ptype Print _loc union.uname t$ ~indent:indent ~name: $ <:expr< $str:c$ >> $ x >> $ >> *)
(*   in *)
(*   let last_case = *)
(*     <:match_case< ( $ <:patt< $uid:union.unparsed_constr$ >> $  $ <:patt< $lid:"x"$ >> $ ) -> *)
(*                   $ <:expr< $fun_of_ptype Print _loc union.uname union.unparsed_type$ *)
(*                                   ~indent:indent ~name:(name ^ "[Unparsed]") x >> $ >> *)
(*   in *)
(*   let cases = (List.map mk_case (keep_unique_cons union.uchoices))@[last_case] in *)
(*   let body = <:expr< fun [ $list:cases$ ] >> in *)
(*   [ mk_multiple_args_fun _loc ("print_" ^ union.uname) []  *)
(*       ~optargs:(["indent", <:expr< $str:""$ >>; "name", <:expr< $str:union.uname$ >> ]) body ] *)


(* (\* Alias *\) *)

(* let mk_alias_parse_fun _loc alias = *)
(*   let body = <:expr< $fun_of_ptype Parse _loc alias.aname alias.atype$ >> in *)
(*   [ mk_multiple_args_fun _loc ("parse_" ^ alias.aname) alias.aparse_params body ] *)

(* let mk_alias_lwt_parse_fun _loc alias = *)
(*   if alias.ado_lwt then begin *)
(*     let body = <:expr< $fun_of_ptype LwtParse _loc alias.aname alias.atype$ >> in *)
(*     [ mk_multiple_args_fun _loc ("lwt_parse_" ^ alias.aname) alias.aparse_params body ] *)
(*   end else [] *)

(* let mk_alias_dump_fun _loc alias = *)
(*   let body = <:expr< $fun_of_ptype Dump _loc alias.aname alias.atype$ >> in *)
(*   [ mk_multiple_args_fun _loc ("dump_" ^ alias.aname) alias.adump_params body ] *)
  
(* let mk_alias_print_fun _loc alias = *)
(*   let body = <:expr< $fun_of_ptype Print _loc alias.aname alias.atype$ ~indent:indent ~name:name >> in *)
(*   [ mk_multiple_args_fun _loc ("print_" ^ alias.aname) []  *)
(*       ~optargs:(["indent", <:expr< $str:""$ >>; "name", <:expr< $str:alias.aname$ >> ]) body ] *)


(* (\* ASN1 Alias *\) *)

(* let split_header _loc (hdr, isC) = *)
(*   let _c, _t = match hdr with *)
(*     | Universal t -> <:expr< Asn1Engine.C_Universal >>, <:expr< Asn1Engine.$uid:t$ >> *)
(*     | Header (c, t) -> <:expr< Asn1Engine.$uid:c$ >>, <:expr< Asn1Engine.T_Unknown $int:string_of_int t$ >> *)
(*   in <:expr< ( $_c$, $exp_bool _loc isC$, $_t$ ) >> *)

(* let mk_asn1_alias_parse_fun _loc alias = *)
(*   let header_constraint = split_header _loc alias.aaheader *)
(*   and parse_content = fun_of_ptype Parse _loc (alias.aaname ^ "_content") alias.aatype in *)
(*   let body = *)
(*     if alias.aalist *)
(*     then <:expr< Asn1Engine.extract_der_seqof $str:alias.aaname$ $header_constraint$ $parse_content$ >> *)
(*     else <:expr< Asn1Engine.extract_der_object $str:alias.aaname$ $header_constraint$ $parse_content$ >> *)
(*   in *)
(*   [ mk_multiple_args_fun _loc ("parse_" ^ alias.aaname) alias.aaparse_params body ] *)

(* let mk_asn1_alias_lwt_parse_fun _loc alias = *)
(*   if alias.aado_lwt then begin *)
(*     let header_constraint = split_header _loc alias.aaheader *)
(*     and parse_content = fun_of_ptype Parse _loc (alias.aaname ^ "_content") alias.aatype in *)
(*     let body = *)
(*       if alias.aalist *)
(*       then <:expr< Asn1Engine.lwt_extract_der_seqof $str:alias.aaname$ $header_constraint$ $parse_content$ >> *)
(*       else <:expr< Asn1Engine.lwt_extract_der_object $str:alias.aaname$ $header_constraint$ $parse_content$ >> *)
(*     in *)
(*     [ mk_multiple_args_fun _loc ("lwt_parse_" ^ alias.aaname) alias.aaparse_params body ] *)
(*   end else [] *)

(* let mk_asn1_alias_dump_fun _loc alias = *)
(*   (\* TODO: improve this! *\) *)
(*   let header_constraint = split_header _loc alias.aaheader in *)
(*   let dump_content = fun_of_ptype Dump _loc (alias.aaname ^ "_content") alias.aatype in *)
(*   let body = *)
(*     if alias.aalist *)
(*     then <:expr< Asn1Engine.produce_der_seqof $header_constraint$ $dump_content$ >> *)
(*     else <:expr< Asn1Engine.produce_der_object $header_constraint$ $dump_content$ >> *)
(*   in *)
(*   [ mk_multiple_args_fun _loc ("dump_" ^ alias.aaname) alias.aadump_params body ] *)
  
(* let mk_asn1_alias_print_fun _loc alias = *)
(*   let print_content = fun_of_ptype Print _loc (alias.aaname ^ "_content") alias.aatype in *)
(*   let body = *)
(*     if alias.aalist *)
(*     then <:expr< Parsifal.print_list $print_content$ ~indent:indent ~name:name >> *)
(*     else <:expr< $print_content$ ~indent:indent ~name:name >> *)
(*   in *)
(*   [ mk_multiple_args_fun _loc ("print_" ^ alias.aaname) []  *)
(*       ~optargs:(["indent", <:expr< $str:""$ >>; "name", <:expr< $str:alias.aaname$ >> ]) body ] *)

(* (\* ASN1 Union *\) *)

(* let mk_asn1_union_parse_fun _loc union = *)
(*   let mk_case (_loc, p, c, t) = *)
(*     let parse_fun = fun_of_ptype Parse _loc union.uname t in *)
(*     <:match_case< $p$ -> $ <:expr< $uid:c$ >> $ ($parse_fun$ new_input) >> *)
(*   in *)
(*   let parsed_cases = List.map mk_case union.uchoices *)
(*   and last_case = <:match_case< (c, _, t) as h -> *)
(*     $ <:expr< $uid:union.unparsed_constr$ (Asn1PTypes.mk_object c t (Asn1PTypes.parse_der_object_content h new_input)) >> $ *)
(*   >> in *)
(*   let body = <:expr< *)
(*     let aux h new_input = match h with *)
(*       [ $list:(parsed_cases@[last_case])$ ] *)
(*     in *)
(*     if Parsifal.should_enrich $lid:"enrich_" ^ union.uname$ input.Parsifal.enrich *)
(*     then Asn1PTypes.advanced_der_parse aux input *)
(*     else $ <:expr< $uid:union.unparsed_constr$ (Asn1PTypes.parse_der_object input) >> $ >> *)
(*   and lwt_body = <:expr< *)
(*     let aux h new_input = match h with *)
(*       [ $list:(parsed_cases@[last_case])$ ] *)
(*     in *)
(*     if Parsifal.should_enrich $lid:"enrich_" ^ union.uname$ input.Parsifal.lwt_enrich *)
(*     then Asn1PTypes.lwt_advanced_der_parse aux input *)
(*     else Lwt.bind (Asn1PTypes.lwt_parse_der_object input) (fun o -> $ <:expr< Lwt.return ($uid:union.unparsed_constr$ o) >> $) >> *)
(*   in *)
(*   let params = union.uparse_params@["input"] in *)
(*   if union.udo_lwt then [ *)
(*     mk_multiple_args_fun _loc ("parse_" ^ union.uname) params body; *)
(*     mk_multiple_args_fun _loc ("lwt_parse_" ^ union.uname) params lwt_body *)
(*   ] else [ mk_multiple_args_fun _loc ("parse_" ^ union.uname) params body ] *)

(* let rec expr_of_pat = function *)
(*   | PaApp (_loc, p1, p2) -> ExApp (_loc, expr_of_pat p1, expr_of_pat p2) *)
(*   | PaCom (_loc, p1, p2) -> ExCom (_loc, expr_of_pat p1, expr_of_pat p2) *)
(*   | PaTup (_loc, p) -> ExTup (_loc, expr_of_pat p) *)
(*   | PaAli (_, p, _) -> expr_of_pat p *)
(*   | PaId (_loc, i) -> ExId (_loc, i) *)
(*   | PaInt (_loc, i) -> ExInt (_loc, i) *)
(*   | p -> Loc.raise (loc_of_patt p) (Failure "pattern not supported for asn1_unions") *)

(* let mk_asn1_union_dump_fun _loc union = *)
(*   let mk_case (_loc, p, c, t) = *)
(*     <:match_case< ( $ <:patt< $uid:c$ >> $  $ <:patt< $lid:"x"$ >> $ ) -> *)
(*     $ <:expr< Asn1Engine.produce_der_object $expr_of_pat p$ $fun_of_ptype Dump _loc union.uname t$ x >> $ >> *)
(*   in *)
(*   let last_case = *)
(*     <:match_case< ( $ <:patt< $uid:union.unparsed_constr$ >> $  $ <:patt< $lid:"o"$ >> $ ) -> Asn1PTypes.dump_der_object o >> *)
(*   in *)
(*   let cases = (List.map mk_case union.uchoices)@[last_case] in *)
(*   let body = <:expr< fun [ $list:cases$ ] >> in *)
(*   [ mk_multiple_args_fun _loc ("dump_" ^ union.uname) union.udump_params body ] *)


(************************)
(* Camlp4 grammar rules *)
(************************)


(* Useful functions *)
let check_options construction options =
  let rec aux opts = match construction, opts with
    | Enum _, (_loc, ParseParam _)::_
    | Enum _, (_loc, DumpParam _)::_ ->
      Loc.raise _loc (Failure "params are not allowed for an enum.")

    | _, (_, ParseParam l)::r ->
      let os, ps, ds = aux r in
      os, l::ps, ds
    | _, (_, DumpParam l)::r ->
      let os, ps, ds = aux r in
      os, ps, l::ds

    | (Enum _|Struct _|Alias _|ASN1Alias _), (_loc, EnrichByDefault)::_ ->
      Loc.raise _loc (Failure "enrich is only allowed for unions.")
    | (Enum _|Struct _|Alias _|ASN1Alias _), (_loc, ExhaustiveChoices)::_ ->
      Loc.raise _loc (Failure "exhaustive is only allowed for unions.")

    | Enum _, (_, LittleEndian)::r ->
      let os, ps, ds = aux r in
      LittleEndian::os, ps, ds
    | _, (_loc, LittleEndian)::_ ->
      Loc.raise _loc (Failure "little_endian is only allowed for enums.")

    | _, (_, o)::r ->
      let os, ps, ds = aux r in
      o::os, ps, ds
    | _, [] -> [], [], []
  in
  let o, p, d = aux options in
  o, List.concat p, List.concat d

let mk_parsifal_construction _loc name raw_opts specific_descr =
  let options, parse_params, dump_params = check_options specific_descr raw_opts in
  let pc = { name = lid_of_ident name;
	     options = options;
	     parse_params = parse_params;
	     dump_params = dump_params;
	     construction = specific_descr }
  and funs = [ mk_decls;
	       mk_type;
	       mk_specific_funs ] in
  let rec mk_sequence = function
    | [] -> <:str_item< >>
    | [si] -> <:str_item< $si$ >>
    | si::r -> <:str_item< $si$; $mk_sequence r$ >>
  in
  mk_sequence (List.concat (List.map (fun f -> f _loc pc) funs))


EXTEND Gram
  GLOBAL: str_item;

  option_list: [[
    -> []
  | "["; "]" -> []
  | "["; _opts = expr; "]" -> opts_of_seq_expr _opts
  ]];


  enum_unknown_behaviour: [[
    "Exception"; x = ident -> Exception (uid_of_ident x)
  | "UnknownVal"; x = ident -> UnknownVal (uid_of_ident x)
  ]];


  ptype_decorator: [[
    "("; e = expr; ")" -> (None, Some e)
  | "["; e = expr; "]" -> (Some e, None)
  | "["; e1 = expr; "]"; "("; e2 = expr; ")" -> (Some e1, Some e2)
  | -> (None, None)
  ]];

  ptype: [[
    "("; t = SELF; ")" -> t
  | type_name = ident; e = ptype_decorator; t = OPT [ "of"; _t = ptype -> _t ] ->
    ptype_of_ident type_name e t
  ]];


  struct_field: [[
    attribute = OPT [
      "optional" -> Optional;
    | "parse_checkpoint" -> ParseCheckpoint;
    | "parse_field" -> ParseField
    ]; name = ident; ":"; field = ptype  ->
    (_loc, lid_of_ident name, field, attribute)
  ]];


  union_choice: [[
    "|"; discr_val = patt; "->"; constructor = ident; "of"; t = ptype ->
      (_loc, discr_val, uid_of_ident constructor, t)
  | "|"; discr_val = patt; "->"; constructor = ident ->
      (_loc, discr_val, uid_of_ident constructor, PT_Empty)
  ]];

  union_unparsed_behaviour: [[
    unparsed_const = ident -> (uid_of_ident unparsed_const, None)
  | unparsed_const = ident; "of"; unparsed_type = ptype -> (uid_of_ident unparsed_const, Some unparsed_type)
  ]];


  asn1_aliased_type_decorator: [[
    "["; tag = ident; "]" -> Some (Universal (uid_of_ident tag))
  | "["; aclass = ident; "," ; tag = INT; "]" -> Some (Header (uid_of_ident aclass, int_of_string tag))
  | -> None
  ]];


  str_item: [[
    "enum"; name = ident; raw_opts = option_list;
    "("; sz = INT; ","; u_b = enum_unknown_behaviour; ")";
    "="; _choices = match_case ->
    let enum_descr = Enum {
      size = int_of_string sz;
      echoices = choices_of_match_cases _choices;
      unknown_behaviour = u_b;
    } in
    mk_parsifal_construction _loc name raw_opts enum_descr
      
  | "struct"; name = ident; raw_opts = option_list; "=";
    "{"; fields = LIST1 struct_field SEP ";"; "}" ->
    mk_parsifal_construction _loc name raw_opts (Struct fields)

  | "union"; name = ident; raw_opts = option_list;
    "("; u_b = union_unparsed_behaviour; ")";
    "="; choices = LIST1 union_choice ->
    let union_descr = Union {
      uchoices = choices;
      unparsed_constr = fst u_b;
      unparsed_type = pop_option (PT_String (Remaining, true)) (snd u_b);
    } in
    mk_parsifal_construction _loc name raw_opts union_descr

  | "alias"; name = ident; raw_opts = option_list;
    "="; type_aliased = ptype ->
    let alias_descr = Alias type_aliased in
    mk_parsifal_construction _loc name raw_opts alias_descr

  | "asn1_alias"; name = ident; raw_opts = option_list;
    "="; alias_sort = ident; asn1_hdr = asn1_aliased_type_decorator; t = ptype ->
    let hdr, is_list_of = asn1_alias_of_ident alias_sort asn1_hdr in
    let aa_descr = ASN1Alias {
      aalist = is_list_of;
      aaheader = hdr;
      aatype = t;
    } in
    mk_parsifal_construction _loc name raw_opts aa_descr

  | "asn1_alias"; name = ident; raw_opts = option_list ->
    let real_name = lid_of_ident name in
    let aa_descr = ASN1Alias {
      aalist = false;
      aaheader = (Universal "T_Sequence", true);
      aatype = (PT_Custom (None, real_name ^ "_content", [], []))
    } in
    mk_parsifal_construction _loc name raw_opts aa_descr      

  | "asn1_union"; name = ident; raw_opts = option_list;
    "("; u_b = union_unparsed_behaviour; ")";
    "="; choices = LIST1 union_choice ->
    (* TODO: Check that snd u_b == None *)
    let asn1_union_descr = ASN1Union {
      uchoices = choices;
      unparsed_constr = fst u_b;
      unparsed_type = PT_Custom (Some "Asn1PTypes", "der_object", [], []);
    } in
    mk_parsifal_construction _loc name raw_opts asn1_union_descr

  ]];
END
;;
