open Camlp4
open Camlp4.PreCast
open Camlp4.PreCast.Ast
open Syntax
open ParsifalHelpers



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

type 'a choice = Loc.t * string * 'a   (* loc, constructor name *)


(* Enums *)
type enum_unknown_behaviour =
  | UnknownVal of string
  | Exception of string

type enum_description = {
  size : int;
  echoices : (string * string) choice list;     (* int value for enum, display string *)
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
type field_attribute = NoFieldAttr | Optional | ParseCheckpoint | ParseField
type struct_description = (Loc.t * string * ptype * field_attribute) list


(* Unions *)
(* ASN1 Unions *)
type union_description = {
  uchoices : (patt * ptype) choice list;  (* discriminating value, subtype *)
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

let (<.>) c o = List.mem o c.options



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
    [_loc, c, (i, s)]
  | McArr (_loc, <:patt< $int:i$ >>, <:expr< >>, <:expr< $uid:c$ >> ) ->
    [_loc, c, (i, c)]
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




(*******************************)
(* OCaml initial definitions   *)
(*   ParsifalSyntax -> OCaml   *)
(*******************************)

(* Common useful functions *)

(* TODO: if two lines are inconsistent, there is no warning...      *)
(*       for enums, we only need to check the 4th field is the same *)
(*       for unions it is more complicated                          *)

let keep_unique_cons (constructors : 'a choice list) =
  let rec _keep_unique_cons names accu = function
  | [] -> List.rev accu
  | ((_, n, _) as c)::r ->
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
  if opt = Optional then <:ctyp< option $real_t$ >> else real_t

let keep_built_fields (_, _, _, a) = a <> ParseCheckpoint
let keep_real_fields (_, _, _, a) = (a <> ParseCheckpoint) && (a <> ParseField)

let split_header _loc (hdr, isC) =
  let _c, _t = match hdr with
    | Universal t -> <:expr< Asn1Engine.C_Universal >>, <:expr< Asn1Engine.$uid:t$ >>
    | Header (c, t) -> <:expr< Asn1Engine.$uid:c$ >>, <:expr< Asn1Engine.T_Unknown $int:string_of_int t$ >>
  in <:expr< ( $_c$, $exp_bool _loc isC$, $_t$ ) >>


(* Specific declarations for enums/unions *)

let mk_decls _loc c =
  match c.construction with
  | Enum {unknown_behaviour = Exception e} ->
    [ <:str_item< exception  $typ:<:ctyp< $uid:e$ >>$  >> ]
  | Union union | ASN1Union union ->
    let enrich_bool = c <.> EnrichByDefault in
    let bool_name = <:patt< $lid:"enrich_" ^ c.name$ >>
    and bool_val = <:expr< ref $exp_bool _loc enrich_bool$ >> in
    [ <:str_item< value $ <:binding< $pat:bool_name$ = $exp:bool_val$ >> $ >> ]
  | _ -> []


(* mk_type function *)

let mk_type _loc c =
  let type_body = match c.construction with
    | Enum enum ->
      let ctors = List.map (fun (_loc, n, _) -> <:ctyp< $uid:n$ >>) (keep_unique_cons enum.echoices) in
      let suffix_choice = match enum.unknown_behaviour with
	| UnknownVal v -> [ <:ctyp< $ <:ctyp< $uid:v$ >> $ of int >> ]
	| _ -> []
      in
      <:ctyp< [ $list:ctors@suffix_choice$ ] >>

    | Struct fields ->
      let mk_line (_loc, n, t, opt) = <:ctyp< $lid:n$ : $ocaml_type_of_field_type _loc t opt$ >> in
      let ctyp_fields = List.map mk_line (List.filter keep_built_fields fields) in
      <:ctyp< { $list:ctyp_fields$ } >>

    | Union union
    | ASN1Union union ->
      let rec mk_ctors = function
	| [] ->
	  [ <:ctyp< $ <:ctyp< $uid:union.unparsed_constr$ >> $ of
	      $ocaml_type_of_ptype _loc union.unparsed_type$ >> ]
	| (_loc, n, (_, PT_Empty))::r -> 
	  (<:ctyp< $uid:n$ >>)::(mk_ctors r)
	| (_loc, n, (_, t))::r ->
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
      let mk_case (_loc, n, (_, d)) = <:patt< $uid:n$ >>, <:expr< $str:d$ >> in
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
      let mk_case (_loc, n, (v, _)) = <:patt< $uid:n$ >>, <:expr< $int:v$ >> in
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
      let mk_case (_loc, n, (v, _)) = <:patt< $int:v$ >>, <:expr< $uid:n$ >> in
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
      let mk_case (_loc, n, (_, d)) = <:patt< $str:d$ >>, <:expr< $uid:n$ >> in
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



(*********************)
(* PARSING FUNCTIONS *)
(*********************)

let rec parse_fun_of_ptype lwt_fun _loc name t =
  let prefix = if lwt_fun then "lwt_parse_" else "parse_" in
  let mkf fname = exp_qname _loc (Some "Parsifal") (prefix ^ fname) in
  match t with
    | PT_Empty -> Loc.raise _loc (Failure "Empty types should never be concretized")
    | PT_Int int_t -> mkf int_t

    | PT_String (ExprLen e, _) -> <:expr< $mkf "string"$ $e$ >>
    | PT_String (VarLen int_t, _) -> <:expr< $mkf "varlen_string"$ $str:name$ $mkf int_t$ >>
    | PT_String (Remaining, _) -> mkf "rem_string"

    | PT_Custom (m, n, e, _) ->
      apply_exprs _loc (exp_qname _loc m (prefix ^ n)) e

    | PT_List (ExprLen e, subtype) ->
      <:expr< $mkf "list"$ $e$
              $parse_fun_of_ptype lwt_fun _loc name subtype$ >>
    | PT_List (Remaining, subtype) ->
      <:expr< $mkf "rem_list"$
              $parse_fun_of_ptype lwt_fun _loc name subtype$ >>
    | PT_List (VarLen int_t, subtype) ->
      <:expr< $mkf "varlen_list"$ $str:name$ $mkf int_t$
              $parse_fun_of_ptype false _loc name subtype$ >>

    | PT_Array (e, subtype) ->
      <:expr< $mkf "array"$ $e$ $parse_fun_of_ptype lwt_fun _loc name subtype$ >>

    | PT_Container (ExprLen e, subtype) ->
      <:expr< $mkf "container"$ $str:name$ $e$
              $parse_fun_of_ptype false _loc name subtype$ >>
    | PT_Container (VarLen int_t, subtype) ->
      <:expr< $mkf "varlen_container"$ $str:name$ $mkf int_t$
              $parse_fun_of_ptype false _loc name subtype$ >>
    | PT_Container (Remaining, subtype) ->
      Loc.raise _loc (Failure "Container without length spec are not allowed")      

    | PT_CustomContainer (m, n, e, _, subtype) ->
      apply_exprs _loc (exp_qname _loc m (prefix ^ n))
	(e@[parse_fun_of_ptype false _loc name subtype])



let mk_parse_fun lwt_fun _loc c =
  let prefix = if lwt_fun then "lwt_" else "" in
  let add_qprefix fname = exp_qname _loc (Some "Parsifal") (prefix ^ fname) in

  let mk_return e = if lwt_fun then <:expr< Lwt.return $e$ >> else e
  and mk_compose f g x = (* f (g x) *)
    if lwt_fun
    then <:expr< Lwt.bind ($g$ $x$) (Lwt.wrap1 $f$) >>
    else <:expr< $f$ ($g$ $x$) >>
  and mk_let_in x v e = (* let x = v in e *)
    if lwt_fun
    then <:expr< Lwt.bind ($v$) (fun $lid:x$ -> $e$) >> 
    else <:expr< let $lid:x$ = $v$ in $e$ >>
  and mk_union_res f cons = (* Cons (f input) *)
    if lwt_fun
    then <:expr< Lwt.bind ($f$ input) (fun x -> Lwt.return ($uid:cons$ x)) >>
    else <:expr< $uid:cons$ ($f$ input) >>
  in

  let body = match c.construction with
    | _ when not (c <.> DoLwt) && lwt_fun -> []

    | Enum enum ->
      if enum.size mod 8 = 0 then begin
	let le = (if c <.> LittleEndian then "le" else "") in
	let parse_int_fun = add_qprefix ("parse_uint" ^ (string_of_int enum.size) ^ le)
	and eoi = <:expr< $lid:c.name ^ "_of_int"$ >> in
	[ mk_compose eoi parse_int_fun <:expr< input >> ]
      end else []

    | Struct fields ->
      let rec parse_fields = function
	| [] ->
	  let single_assign (_loc, n, _, _) = <:rec_binding< $lid:n$ = $exp: <:expr< $lid:n$ >> $ >> in
	  let assignments = List.map single_assign (List.filter keep_built_fields fields) in
	  mk_return <:expr< { $list:assignments$ } >>
	| (_loc, n, t, attribute)::r ->
	  let tmp = parse_fields r
	  and f = parse_fun_of_ptype lwt_fun _loc n t in
	  let parse_f = match lwt_fun, attribute with
	    | _, Optional -> <:expr< $add_qprefix "try_parse"$ $f$ >>
	    | _, _ -> f
	  in
	  mk_let_in n <:expr< $parse_f$ input >> tmp
      in [parse_fields fields]

    | Union union ->
      let mk_case = function
	| (_loc, cons, (p, PT_Empty)) ->
	  <:match_case< $p$ -> $ mk_return <:expr< $uid:cons$ >> $ >>
	| (_loc, cons, (p, t)) ->
	  let f = parse_fun_of_ptype lwt_fun _loc c.name t in
	  <:match_case< $p$ -> $mk_union_res f cons$ >>
      and mk_unparsed =
	let f = parse_fun_of_ptype lwt_fun _loc c.name union.unparsed_type in
	mk_union_res f union.unparsed_constr
      in
      let parsed_cases = List.map mk_case union.uchoices
      and last_case = <:match_case< _ -> $mk_unparsed$ >> in
      let cases = if c <.> ExhaustiveChoices then parsed_cases else parsed_cases@[last_case] in
      [ <:expr< if Parsifal.should_enrich $lid:"enrich_" ^ c.name$ input.$add_qprefix "enrich"$
	then match discriminator with [ $list:cases$ ]
	else $mk_unparsed$ >> ]

    | Alias atype ->
      [ <:expr< $parse_fun_of_ptype lwt_fun _loc c.name atype$ input >> ]

    | ASN1Alias alias ->
      let header_constraint = split_header _loc alias.aaheader
      and parse_content = parse_fun_of_ptype false _loc (c.name ^ "_content") alias.aatype in
      let meta_f_name = if alias.aalist then "extract_der_seqof" else "extract_der_object" in
      let meta_f = exp_qname _loc (Some "Asn1Engine") (prefix ^ meta_f_name) in
      [ <:expr< $meta_f$ $str:c.name$ $header_constraint$ $parse_content$ input >> ]

    | ASN1Union union ->
      let mk_case (_loc, cons, (p, t)) =
	let parse_fun = parse_fun_of_ptype false _loc c.name t in
	<:match_case< $p$ -> $ <:expr< $uid:cons$ ($parse_fun$ new_input) >> $ >>
      in
      let parsed_cases = List.map mk_case union.uchoices
      and last_case =
	<:match_case< (c, _, t) as h -> $ <:expr< $uid:union.unparsed_constr$
          (Asn1PTypes.mk_object c t (Asn1PTypes.parse_der_object_content h new_input)) >> $ >>
      in
      let enrich_flag = <:expr< input.$add_qprefix "enrich"$ >>
      and wrapper_fun = exp_qname _loc (Some "Asn1PTypes") (prefix ^ "advanced_der_parse")
      and default_fun = exp_qname _loc (Some "Asn1PTypes") (prefix ^ "parse_der_object") in

      [ <:expr<
	  let aux h new_input = match h with
	      [ $list:(parsed_cases@[last_case])$ ]
	  in
	  if Parsifal.should_enrich $lid:"enrich_" ^ c.name$ $enrich_flag$
	  then $wrapper_fun$ aux input
	  else $mk_union_res default_fun union.unparsed_constr$ >> ]

  in
  let res_name = prefix ^ "parse_" ^ c.name in
  List.map (mk_multiple_args_fun _loc res_name (c.parse_params@["input"])) body



let mk_exact_parse_fun _loc c =
  if c <.> ExactParser then begin
    let partial_params = List.map (fun p -> <:expr< $lid:p$ >>) c.parse_params
    and params = c.parse_params@["input"] in
    let parse_fun = apply_exprs _loc (exp_qname _loc None ("parse_" ^ c.name)) partial_params in
    let body = <:expr< Parsifal.exact_parse $parse_fun$ input >> in
    [ mk_multiple_args_fun _loc ("exact_parse_" ^ c.name) params body ]
  end else []



(*********************)
(* DUMPING FUNCTIONS *)
(*********************)

let rec dump_fun_of_ptype _loc name t =
  let mkf fname = exp_qname _loc (Some "Parsifal") ("dump_" ^ fname) in
  match t with
    | PT_Empty -> Loc.raise _loc (Failure "Empty types should never be concretized")
    | PT_Int int_t -> mkf int_t

    | PT_String (VarLen int_t, _) -> <:expr< $mkf "varlen_string"$ $mkf int_t$ >>
    | PT_String (_, _) -> mkf "string"

    | PT_Custom (m, n, _, e) -> apply_exprs _loc (exp_qname _loc m ("dump_" ^ n)) e

    | PT_List (VarLen int_t, subtype) ->
      <:expr< $mkf "varlen_list"$ $mkf int_t$ $dump_fun_of_ptype _loc name subtype$ >>
    | PT_List (_, subtype) ->
      <:expr< $mkf "list"$ $dump_fun_of_ptype _loc name subtype$ >>
    | PT_Array (_, subtype) ->
      <:expr< $mkf "array"$ $dump_fun_of_ptype _loc name subtype$ >>
    | PT_Container (VarLen int_t, subtype) ->
      <:expr< $mkf "container"$ $mkf int_t$ $dump_fun_of_ptype _loc name subtype$ >>
    | PT_Container (_, subtype) -> dump_fun_of_ptype _loc name subtype

    | PT_CustomContainer (m, n, _, e, subtype) ->
      apply_exprs _loc (exp_qname _loc m ("dump_" ^ n))
	(e@[dump_fun_of_ptype _loc name subtype])


let mk_dump_fun _loc c =
  let add_qprefix fname = exp_qname _loc (Some "Parsifal") ("dump_" ^ fname) in

  let body = match c.construction with
  | Enum enum ->
    if enum.size mod 8 = 0 then begin
      let le = (if c <.> LittleEndian then "le" else "") in
      let dump_int_fun = add_qprefix ("uint" ^ (string_of_int enum.size) ^ le)
      and ioe = <:expr< $lid:"int_of_" ^ c.name$ >> in
      [ <:expr< $dump_int_fun$ ($ioe$ $lid:c.name$) >> ]
    end else []

  | Struct fields ->
    let dump_one_field (_loc, n, t, attr) =
      let raw_f = dump_fun_of_ptype _loc n t in
      let f = if attr = Optional then <:expr< Parsifal.try_dump $raw_f$ >> else raw_f in
      <:expr< $f$ $lid:c.name$.$lid:n$ >>
    in
    let fields_dumped_expr = exp_of_list _loc (List.map dump_one_field (List.filter keep_real_fields fields)) in
    [ <:expr< let fields_dumped = $fields_dumped_expr$ in
	      String.concat "" fields_dumped >> ]

  | Union union ->
    let mk_case = function
      | _loc, cons, (_, PT_Empty) ->
	<:match_case< $ <:patt< $uid:cons$ >> $ -> "" >>
      | _loc, cons, (n, t) ->
	<:match_case< ( $ <:patt< $uid:cons$ >> $  x ) ->
        $ <:expr< $dump_fun_of_ptype _loc c.name t$ x >> $ >>
    and last_case =
      <:match_case< ( $ <:patt< $uid:union.unparsed_constr$ >> $  x ) ->
      $ <:expr< $dump_fun_of_ptype _loc c.name union.unparsed_type$ x >> $ >>
    in
    let cases = (List.map mk_case (keep_unique_cons union.uchoices))@[last_case] in
    [ <:expr< (fun [ $list:cases$ ]) $lid:c.name$ >> ]

  | Alias atype -> [ <:expr< $dump_fun_of_ptype _loc c.name atype$ $lid:c.name$ >> ]

  | ASN1Alias alias ->
    let header_constraint = split_header _loc alias.aaheader in
    let dump_content = dump_fun_of_ptype _loc (c.name ^ "_content") alias.aatype in
    let meta_f_name = if alias.aalist then "produce_der_seqof" else "produce_der_object" in
    let meta_f = exp_qname _loc (Some "Asn1Engine") meta_f_name in
    [ <:expr< $meta_f$ $header_constraint$ $dump_content$ $lid:c.name$ >> ]

  | ASN1Union union ->
    let mk_case (_loc, cons, (p, t)) =
      <:match_case< ( $ <:patt< $uid:cons$ >> $  x ) ->
      $ <:expr< Asn1Engine.produce_der_object $expr_of_pat p$ $dump_fun_of_ptype _loc c.name t$ x >> $ >>
    and last_case =
      <:match_case< ( $ <:patt< $uid:union.unparsed_constr$ >> $  o ) -> Asn1PTypes.dump_der_object o >>
    in
    let cases = (List.map mk_case union.uchoices)@[last_case] in
    [ <:expr< (fun [ $list:cases$ ]) $lid:c.name$ >> ]

  in List.map (mk_multiple_args_fun _loc ("dump_" ^ c.name) (c.dump_params@[c.name])) body



(**********************)
(* PRINTING FUNCTIONS *)
(**********************)

let rec print_fun_of_ptype _loc name t =
  let mkf fname = exp_qname _loc (Some "Parsifal") ("print_" ^ fname) in
  match t with
    | PT_Empty -> Loc.raise _loc (Failure "Empty types should never be concretized")
    | PT_Int int_t -> mkf int_t

    | PT_String (_, true) -> mkf "binstring"
    | PT_String (_, false) -> mkf "printablestring"

    | PT_Custom (m, n, _, _) -> exp_qname _loc m ("print_" ^ n)

    | PT_List (_, subtype) -> <:expr< $mkf "list"$ $print_fun_of_ptype _loc name subtype$ >>
    | PT_Array (_, subtype) -> <:expr< $mkf "array"$ $print_fun_of_ptype _loc name subtype$ >>
    | PT_Container (_, subtype)
    | PT_CustomContainer (_, _, _, _, subtype) -> print_fun_of_ptype _loc name subtype



let mk_print_fun _loc c =
  let add_qprefix fname = exp_qname _loc (Some "Parsifal") ("print_" ^ fname) in

  let body = match c.construction with
  | Enum enum ->
    let ioe = <:expr< $lid:"int_of_" ^ c.name$ >>
    and soe = <:expr< $lid:"string_of_" ^ c.name$ >>
    and print_fun = add_qprefix "enum" in
    <:expr< $print_fun$ $soe$ $ioe$ $int:string_of_int (enum.size / 4)$
      ~indent:indent ~name:name $lid:c.name$ >>

  | Struct fields ->
    let print_one_field (_loc, n, t, attr) =
      let raw_f = print_fun_of_ptype _loc n t in
      let f = if attr = Optional then <:expr< Parsifal.try_print $raw_f$ >> else raw_f in
      <:expr< $f$ ~indent:new_indent ~name:$str:n$ $lid:c.name$.$lid:n$ >>
    in
    let fields_printed_expr = exp_of_list _loc (List.map print_one_field (List.filter keep_real_fields fields)) in
    <:expr< let new_indent = indent ^ "  " in
	    let fields_printed = $fields_printed_expr$ in
	    indent ^ name ^ " {\\n" ^
	      (String.concat "" fields_printed) ^
	      indent ^ "}\\n" >>

  | Union union
  | ASN1Union union ->
    let mk_case = function
      | _loc, cons, (_, PT_Empty) ->
	<:match_case< $ <:patt< $uid:cons$ >> $ ->
	Parsifal.print_binstring ~indent:indent ~name:name "" >>
      | (_loc, cons, (n, t)) ->
	<:match_case< ( $ <:patt< $uid:cons$ >> $  x ) ->
	$ <:expr< $print_fun_of_ptype _loc c.name t$ ~indent:indent ~name: $ <:expr< $str:cons$ >> $ x >> $ >>
    in
    let last_case =
      <:match_case< ( $ <:patt< $uid:union.unparsed_constr$ >> $  x ) ->
      $ <:expr< $print_fun_of_ptype _loc c.name union.unparsed_type$
        ~indent:indent ~name:(name ^ "[Unparsed]") x >> $ >>
    in
    let cases = (List.map mk_case (keep_unique_cons union.uchoices))@[last_case] in
    <:expr< (fun [ $list:cases$ ]) $lid:c.name$ >>

  | Alias atype ->
    <:expr< $print_fun_of_ptype _loc c.name atype$ ~indent:indent ~name:name $lid:c.name$ >>

  | ASN1Alias alias ->
    let print_content = print_fun_of_ptype _loc (c.name ^ "_content") alias.aatype in
    if alias.aalist
    then <:expr< Parsifal.print_list $print_content$ ~indent:indent ~name:name $lid:c.name$ >>
    else <:expr< $print_content$ ~indent:indent ~name:name $lid:c.name$ >>

  in
  let optargs = ["indent", <:expr< $str:""$ >>; "name", <:expr< $str:c.name$ >>] in
  [ mk_multiple_args_fun _loc ("print_" ^ c.name) [c.name] ~optargs:optargs body ]




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
  let options, raw_parse_params, dump_params = check_options specific_descr raw_opts in
  let parse_params = match specific_descr with
    | Union _ -> raw_parse_params@["discriminator"]
    | _ -> raw_parse_params
  in
  let pc = { name = lid_of_ident name;
	     options = options;
	     parse_params = parse_params;
	     dump_params = dump_params;
	     construction = specific_descr }
  and funs = [ mk_decls; mk_type; mk_specific_funs;
	       mk_parse_fun false; mk_parse_fun true; mk_exact_parse_fun;
	       mk_dump_fun; mk_print_fun ] in
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
    attr = OPT [
      "optional" -> Optional;
    | "parse_checkpoint" -> ParseCheckpoint;
    | "parse_field" -> ParseField
    ]; name = ident; ":"; field = ptype  ->
    match attr with
    | Some a -> (_loc, lid_of_ident name, field, a)
    | None -> (_loc, lid_of_ident name, field, NoFieldAttr)
  ]];

  union_choice: [[
    "|"; discr_val = patt; "->"; constructor = ident; "of"; t = ptype ->
      (_loc, uid_of_ident constructor, (discr_val, t))
  | "|"; discr_val = patt; "->"; constructor = ident ->
      (_loc, uid_of_ident constructor, (discr_val, PT_Empty))
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
