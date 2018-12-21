open Camlp4.PreCast
open Camlp4.PreCast.Ast
open Syntax
open ParsifalHelpers



(********************************************)
(* Types representing the new constructions *)
(********************************************)

(* Common *)

type param_type = ParseParam | DumpParam | BothParam | ContextParam

type parsifal_option =
  | LittleEndian
  | NoAlias
  | EnrichByDefault
  | ExhaustiveChoices
  | Param of (param_type * string) list
  | ExactParser
  | NoDump
  | NoParse
  | NoValueOf

type 'a choice = Loc.t * string * 'a   (* loc, constructor name *)


(* Enums *)
type enum_unknown_behaviour =
  | UnknownVal of string
  | Exception

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
  | PT_Custom of (string option) * string * (param_type * expr) list
  | PT_CustomContainer of (string option) * string * (param_type * expr) list * ptype
    (* PT_CustomContainer (module name, name, param list, subtype) *)


(* Records *)
type field_attribute = NoFieldAttr | Optional | ParseCheckpoint | DumpCheckpoint | ParseField | DumpArg
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
  params : (param_type * string) list;
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
    | <:expr< $lid:"top"$ >>            -> [_loc, ExactParser]
    | <:expr< $lid:"enrich"$ >>         -> [_loc, EnrichByDefault]
    | <:expr< $lid:"exhaustive"$ >>     -> [_loc, ExhaustiveChoices]
    | <:expr< $lid:"parse_param"$ $e$ >>
    | <:expr< $lid:"param"$ $e$ >>      ->
      [_loc, Param (List.map (fun e -> (ParseParam, lid_of_expr e)) (list_of_com_expr e))]
    | <:expr< $lid:"dump_param"$ $e$ >> ->
      [_loc, Param (List.map (fun e -> (DumpParam, lid_of_expr e)) (list_of_com_expr e))]
    | <:expr< $lid:"both_param"$ $e$ >> ->
      [_loc, Param (List.map (fun e -> (BothParam, lid_of_expr e)) (list_of_com_expr e))]
    | <:expr< $lid:"little_endian"$ >>  -> [_loc, LittleEndian]
    | <:expr< $lid:"noalias"$ >>        -> [_loc, NoAlias]
    | <:expr< $lid:"nodump"$ >>         -> [_loc, NoDump]
    | <:expr< $lid:"noparse"$ >>        -> [_loc, NoParse]
    | <:expr< $lid:"novalueof"$ >>      -> [_loc, NoValueOf]

    | _ -> Loc.raise (loc_of_expr e) (Failure "unknown option")
  in
  List.concat (List.map opt_of_exp (list_of_sem_expr expr))


(* Enum choices *)

let rec choices_of_patterns loc cons str accu = function
  | <:patt< $int:i$ >> -> (loc, cons, (i, str))::accu
  | <:patt< $p1$ | $p2$ >> ->
    let new_accu = choices_of_patterns loc cons str accu p1 in
    choices_of_patterns loc cons str new_accu p2
  | PaTup (_, PaCom (_, <:patt< $int:i1$ >>, <:patt< $int:i2$ >>)) ->
    List.map (fun i -> (loc, cons, (string_of_int i, str))) (rev_range [] (int_of_string i1) (int_of_string i2))
  | p -> Loc.raise (loc_of_patt p) (Failure "Invalid choice for an enum pattern")


let rec choices_of_match_cases = function
  | McNil _ -> []
  | McOr (_, m1, m2) ->
    (choices_of_match_cases m1)@(choices_of_match_cases m2)
  | McArr (_loc, p, <:expr< >>, ExTup (_, ExCom (_, <:expr< $uid:c$ >>, <:expr< $str:s$ >> ))) ->
    List.rev (choices_of_patterns _loc c s [] p)
  | McArr (_loc, p, <:expr< >>, <:expr< $uid:c$ >> ) ->
    List.rev (choices_of_patterns _loc c c [] p)
  | mc -> Loc.raise (loc_of_match_case mc) (Failure "Invalid choice for an enum")


(* PTypes *)

let ptype_of_ident name decorators subtype =
  match name, decorators, subtype with
    | <:ident< $lid:"list"$ >>, [], Some t ->
      PT_CustomContainer (Some "BasePTypes", "rem_list", [], t)
    | <:ident< $lid:"list"$ >>, [ParseParam, _], Some t ->
      PT_CustomContainer (None, "list", decorators, t)
    | <:ident< $lid:"list"$ >>,                                      (* Compat Hack: BothParam should not be kept *)
      [ (BothParam|ContextParam), int_t ], Some t ->
      PT_CustomContainer (Some "BasePTypes", "varlen_list", [ContextParam, int_t], t)
    | <:ident< $lid:"list"$ >> as i,  _, _ -> Loc.raise (loc_of_ident i) (Failure "invalid list type")

    | <:ident< $lid:"array"$ >>, [ParseParam, _], Some t ->
      PT_CustomContainer (None, "array", decorators, t)
    | <:ident< $lid:"array"$ >> as i,  _, _ ->  Loc.raise (loc_of_ident i) (Failure "invalid array type")

    | <:ident< $lid:"container"$ >>, [ParseParam, _], Some t ->      (* Compat Hack: should be removed? *)
      PT_CustomContainer (Some "BasePTypes", "container", decorators, t)
    | <:ident< $lid:"container"$ >>,                                 (* Compat Hack: BothParam should not be kept *)
      [ (BothParam|ContextParam), int_t ], Some t ->
      PT_CustomContainer (Some "BasePTypes", "varlen_container", [ContextParam, int_t], t)
    | <:ident< $lid:"container"$ >> as i, _, _ -> Loc.raise (loc_of_ident i) (Failure "invalid container type")

    | <:ident< $lid:"string"$ >>,    [], None -> PT_Custom (Some "BasePTypes", "rem_string", [])
    | <:ident< $lid:"binstring"$ >>, [], None -> PT_Custom (Some "BasePTypes", "rem_binstring", [])
    | <:ident< $lid:"string"$ >>,    [ParseParam, _], None -> PT_Custom (Some "BasePTypes", "string", decorators)
    | <:ident< $lid:"binstring"$ >>, [ParseParam, _], None -> PT_Custom (Some "BasePTypes", "binstring", decorators)
    | <:ident< $lid:"string"$ >>, [(BothParam|ContextParam), int_t], None -> (* Compat Hack *)
      PT_Custom (Some "BasePTypes", "varlen_string", [ContextParam, int_t])
    | <:ident< $lid:"binstring"$ >>, [(BothParam|ContextParam), int_t], None -> (* Compat Hack *)
      PT_Custom (Some "BasePTypes", "varlen_binstring", [ContextParam, int_t])
    | <:ident< $lid:("string" | "binstring")$ >> as i, _, _ -> Loc.raise (loc_of_ident i) (Failure "invalid string type")

    | custom_identifier, _, None ->
      let module_name, name = qname_ident (custom_identifier) in
      PT_Custom (module_name, name, decorators)

    | custom_identifier, _, Some t ->
      let module_name, name = qname_ident (custom_identifier) in
      PT_CustomContainer (module_name, name, decorators, t)


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
  | PT_Custom (None, n, _) -> <:ctyp< $lid:n$ >>
  | PT_Custom (Some m, n, _) -> <:ctyp< $uid:m$.$lid:n$ >>
  | PT_CustomContainer (None, n, _, subtype) -> <:ctyp< $lid:n$ $ocaml_type_of_ptype _loc subtype$ >>
  | PT_CustomContainer (Some m, n, _, subtype) -> <:ctyp< ($uid:m$.$lid:n$) $ocaml_type_of_ptype _loc subtype$ >>

let ocaml_type_of_field_type _loc t opt =
  let real_t = ocaml_type_of_ptype _loc t in
  if opt = Optional then <:ctyp< option $real_t$ >> else real_t


let parsed_attr = function
  | NoFieldAttr | Optional | ParseCheckpoint | ParseField -> true
  | DumpCheckpoint | DumpArg -> false
let built_attr = function
  | NoFieldAttr | Optional | ParseField -> true
  | ParseCheckpoint | DumpCheckpoint | DumpArg -> false
let dumped_attr = function
  | NoFieldAttr | Optional | DumpArg | DumpCheckpoint -> true
  | ParseCheckpoint | ParseField -> false
let filter_attr f fields = List.filter (fun (_, _, _, a) -> f a) fields

let keep_parsed_fields = filter_attr parsed_attr
let keep_built_fields = filter_attr built_attr
let keep_dumped_fields = filter_attr dumped_attr


let split_header _loc (hdr, isC) =
  let _c, _t = match hdr with
    | Universal t -> <:expr< Asn1Engine.C_Universal >>, <:expr< Asn1Engine.$uid:t$ >>
    | Header (c, t) -> <:expr< Asn1Engine.$uid:c$ >>, <:expr< Asn1Engine.T_Unknown $int:string_of_int t$ >>
  in <:expr< ( $_c$, $exp_bool _loc isC$, $_t$ ) >>

let filter_params type_to_keep prefix ps =
  let fp_aux p accu = match type_to_keep, p with
    | ParseParam, (ParseParam, e)
    | DumpParam, (DumpParam, e)
    | _, (BothParam, e) -> e::accu
    | _, (ContextParam, ExId (_loc1, IdLid (_loc2, id))) ->
      (ExId (_loc1, IdLid (_loc2, prefix ^ id)))::accu
    | _, _ -> accu
  in List.fold_right fp_aux ps []

let keep_parse_params ps = List.map snd (List.filter (fun (t, _) -> t <> DumpParam) ps)
let keep_dump_params ps = List.map snd (List.filter (fun (t, _) -> t <> ParseParam) ps)


(* Specific declarations for enums/unions *)

let mk_decls _loc c =
  match c.construction with
  | Union _ | ASN1Union _ ->
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
      let ctyp_fields = List.map mk_line (keep_built_fields fields) in
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
    let mk_pm_fun (fname, argnames, optargnames, cases) =
      let mk_case (p, e) = <:match_case< $p$ -> $e$ >> in
      let cases = List.map mk_case cases in
      let body = <:expr< fun [ $list:cases$ ] >> in
      mk_multiple_args_fun_with_optargs _loc fname argnames optargnames body
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
      (fname, [], [], cases)

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
      (fname, [], [], cases)

    and mk_enum_of_int =
      let mk_case (_loc, n, (v, _)) = <:patt< $int:v$ >>, <:expr< $uid:n$ >> in
      let _cases = List.map mk_case enum.echoices in
      let last_p, last_e, optargs = match enum.unknown_behaviour with
        | UnknownVal v ->
          <:patt< $lid:"i"$ >>,
          <:expr< $ <:expr< $uid:v$ >> $ $ <:expr< $lid:"i"$ >> $ >>,
          []
        | Exception ->
          <:patt< $lid:"i"$ >>,
          <:expr< Parsifal.value_not_in_enum $str:c.name$ $lid:"i"$ $lid:"history"$ >>,
          ["history", <:expr< $uid:"[]"$ >> ]
      in
      let cases = _cases@[last_p, last_e]
      and fname = c.name ^ "_of_int" in
      (fname, [], optargs, cases)

    and mk_enum_of_string =
      let mk_case (_loc, n, (_, d)) = <:patt< $str:d$ >>, <:expr< $uid:n$ >> in
      let _cases = List.map mk_case (keep_unique_cons enum.echoices) in
      let last_p = <:patt< $lid:"s"$ >>
      and eoi = <:expr< $lid:c.name ^ "_of_int"$ >> in
      let last_e = <:expr< $eoi$  (int_of_string s) >> in
      let cases = _cases@[last_p, last_e]
      and fname = c.name ^ "_of_string" in
      (fname, [], [], cases)
    in

    let fns = [mk_int_of_enum; mk_string_of_enum;
               mk_enum_of_int; mk_enum_of_string] in
    List.map mk_pm_fun fns
  | _ -> []



(*********************)
(* PARSING FUNCTIONS *)
(*********************)

let rec parse_fun_of_ptype _loc name t =
  match t with
    | PT_Empty -> Loc.raise _loc (Failure "Empty types should never be concretized")
    | PT_Custom (m, n, e) ->
      apply_exprs _loc (exp_qname _loc m ("parse_" ^ n)) (filter_params ParseParam "parse_" e)
    | PT_CustomContainer (m, n, e, subtype) ->
      apply_exprs _loc (exp_qname _loc m ("parse_" ^ n))
        ((filter_params ParseParam "parse_" e)@
            [ <:expr< $str:name$ >> ; parse_fun_of_ptype _loc name subtype])



let mk_parse_fun _loc c =
  let mkname m fname = exp_qname _loc (Some m) fname in
  let mk_compose f g x = <:expr< $f$ ($g$ $x$) >>             (* f (g x) *)
  and mk_let_in x v e = <:expr< let $lid:x$ = $v$ in $e$ >>   (* let x = v in e *)
  and mk_union_res f cons = <:expr< $uid:cons$ ($f$ input) >> (* Cons (f input) *)
  in

  let body = match c.construction with
    | Enum enum ->
      (* TODO: How can we treat non-aligned 8-bit enums properly and efficiently in most cases *)
      (* Add a AlwaysAligned option? Or on the contrary *)
      (* Rewrite parse_bits to be efficient when things are aligned? *)
      if enum.size mod 8 = 0 then begin
        let le = (if c <.> LittleEndian then "le" else "") in
        let parse_int_fun = mkname "BasePTypes" ("parse_uint" ^ (string_of_int enum.size) ^ le)
        and eoi = <:expr< $lid:c.name ^ "_of_int"$ >> in
        [ mk_compose eoi parse_int_fun <:expr< input >> ]
      end else begin
        let parse_int_fun = <:expr< Parsifal.parse_bits $int:string_of_int enum.size$ >>
        and eoi = <:expr< $lid:c.name ^ "_of_int"$ >> in
        [ mk_compose eoi parse_int_fun <:expr< input >> ]
      end

    | Struct fields ->
      let rec parse_fields = function
        | [] ->
          let single_assign (_loc, n, _, _) = <:rec_binding< $lid:n$ = $exp: <:expr< $lid:n$ >> $ >> in
          let assignments = List.map single_assign (keep_built_fields fields) in
          <:expr< { $list:assignments$ } >>
        | (_loc, n, t, attribute)::r ->
          let tmp = parse_fields r
          and f = parse_fun_of_ptype _loc n t in
          let parse_f = match attribute with
            | Optional -> <:expr< $mkname "Parsifal" "try_parse"$ $f$ >>
            | _ -> f
          in
          mk_let_in n <:expr< $parse_f$ input >> tmp
      in [parse_fields (keep_parsed_fields fields)]

    | Union union ->
      let mk_case = function
        | (_loc, cons, (p, PT_Empty)) ->
          <:match_case< $p$ -> $ <:expr< $uid:cons$ >> $ >>
        | (_loc, cons, (p, t)) ->
          let f = parse_fun_of_ptype _loc c.name t in
          <:match_case< $p$ -> $mk_union_res f cons$ >>
      and mk_unparsed =
        let f = parse_fun_of_ptype _loc c.name union.unparsed_type in
        mk_union_res f union.unparsed_constr
      in
      let parsed_cases = List.map mk_case union.uchoices
      and last_case = <:match_case< _ -> $mk_unparsed$ >> in
      let cases = if c <.> ExhaustiveChoices then parsed_cases else parsed_cases@[last_case] in
      [ <:expr< if Parsifal.should_enrich $lid:"enrich_" ^ c.name$ input.$mkname "Parsifal" "enrich"$
        then match discriminator with [ $list:cases$ ]
        else $mk_unparsed$ >> ]

    | Alias atype ->
      [ <:expr< $parse_fun_of_ptype _loc c.name atype$ input >> ]

    | ASN1Alias alias ->
      let header_constraint = split_header _loc alias.aaheader
      and parse_content = parse_fun_of_ptype _loc (c.name ^ "_content") alias.aatype in
      let meta_f_name = if alias.aalist then "extract_der_seqof" else "extract_der_object" in
      let meta_f = exp_qname _loc (Some "Asn1Engine") (meta_f_name) in
      [ <:expr< $meta_f$ $header_constraint$ $str:c.name$ $parse_content$ input >> ]

    | ASN1Union union ->
      let mk_case (_loc, cons, (p, t)) =
        let parse_fun = parse_fun_of_ptype _loc c.name t in
        <:match_case< $p$ -> $ <:expr< $uid:cons$ ($parse_fun$ new_input) >> $ >>
      in
      let parsed_cases = List.map mk_case union.uchoices
      and last_case =
        <:match_case< (c, _, t) as h -> $ <:expr< $uid:union.unparsed_constr$
          (Asn1PTypes.mk_object c t (Asn1PTypes.parse_der_object_content h new_input)) >> $ >>
      in
      let enrich_flag = <:expr< input.$mkname "Parsifal" "enrich"$ >>
      and wrapper_fun = exp_qname _loc (Some "Asn1PTypes") "advanced_der_parse"
      and default_fun = exp_qname _loc (Some "Asn1PTypes") "parse_der_object" in

      [ <:expr<
          let aux h new_input = match h with
              [ $list:(parsed_cases@[last_case])$ ]
          in
          if Parsifal.should_enrich $lid:"enrich_" ^ c.name$ $enrich_flag$
          then $wrapper_fun$ aux input
          else $mk_union_res default_fun union.unparsed_constr$ >> ]

  in
  let res_name = "parse_" ^ c.name in
  List.map (mk_multiple_args_fun _loc res_name ((keep_parse_params c.params)@["input"])) body



let mk_exact_parse_fun _loc c =
  let partial_params = List.map (fun p -> <:expr< $lid:p$ >>) (keep_parse_params c.params)
  and params = (keep_parse_params c.params)@["input"] in
  let parse_fun = apply_exprs _loc (exp_qname _loc None ("parse_" ^ c.name)) partial_params in
  let body = <:expr< Parsifal.exact_parse $parse_fun$ input >> in
  [ mk_multiple_args_fun _loc ("exact_parse_" ^ c.name) params body ]



(*********************)
(* DUMPING FUNCTIONS *)
(*********************)

let rec dump_fun_of_ptype _loc t =
  match t with
    | PT_Empty -> Loc.raise _loc (Failure "Empty types should never be concretized")
    | PT_Custom (m, n, e) ->
      apply_exprs _loc (exp_qname _loc m ("dump_" ^ n)) (filter_params DumpParam "dump_" e)
    | PT_CustomContainer (m, n, e, subtype) ->
      apply_exprs _loc (exp_qname _loc m ("dump_" ^ n))
        ((filter_params DumpParam "dump_" e)@[dump_fun_of_ptype _loc subtype])


let mk_dump_fun _loc c =
  let body = match c.construction with
  | Enum enum ->
    (* TODO: How can we treat non-aligned 8-bit enums properly and efficiently in most cases *)
    (* Rewrite parse_bits to be efficient when things are aligned? *)
    if enum.size mod 8 = 0 then begin
      let le = (if c <.> LittleEndian then "le" else "") in
      let dump_int_fun = exp_qname _loc (Some "BasePTypes") ("dump_uint" ^ (string_of_int enum.size) ^ le)
      and ioe = <:expr< $lid:"int_of_" ^ c.name$ >> in
      [ <:expr< $dump_int_fun$ buf ($ioe$ $lid:c.name$) >> ]
    end else begin
      let dump_int_fun = <:expr< POutput.add_bits buf $int:string_of_int enum.size$ >>
      and ioe = <:expr< $lid:"int_of_" ^ c.name$ >> in
      [ <:expr< $dump_int_fun$ ($ioe$ $lid:c.name$) >> ]
    end

  | Struct fields ->
    let rec dump_fields = function
    | [] -> <:expr< () >>
    | (_loc, n, t, o)::r ->
      let tmp = dump_fields r in
        match t, o with
        | PT_Empty, DumpArg -> <:expr< let $lid:n$ = $lid:c.name$.$lid:n$ in $tmp$ >>
        | t, DumpCheckpoint ->
          let f = dump_fun_of_ptype _loc t in
          <:expr< let $lid:n$ = $f$ buf in $tmp$ >>
        | t, Optional ->
          let f = <:expr< Parsifal.try_dump $dump_fun_of_ptype _loc t$ >> in
          <:expr< let $lid:"_" ^ n$ = $f$ buf $lid:c.name$.$lid:n$ in $tmp$ >>
        | _ ->
          let f = dump_fun_of_ptype _loc t in
          <:expr< let $lid:"_" ^ n$ = $f$ buf $lid:c.name$.$lid:n$ in $tmp$ >>
    in [dump_fields (keep_dumped_fields fields)]

  | Union union ->
    let mk_case = function
      | _loc, cons, (_, PT_Empty) ->
        <:match_case< $ <:patt< $uid:cons$ >> $ -> () >>
      | _loc, cons, (_, t) ->
        <:match_case< ( $ <:patt< $uid:cons$ >> $  x ) ->
        $ <:expr< $dump_fun_of_ptype _loc t$ buf x >> $ >>
    and last_case =
      <:match_case< ( $ <:patt< $uid:union.unparsed_constr$ >> $  x ) ->
      $ <:expr< $dump_fun_of_ptype _loc union.unparsed_type$ buf x >> $ >>
    in
    let cases = (List.map mk_case (keep_unique_cons union.uchoices))@[last_case] in
    [ <:expr< (fun [ $list:cases$ ]) $lid:c.name$ >> ]

  | Alias atype -> [ <:expr< $dump_fun_of_ptype _loc atype$ buf $lid:c.name$ >> ]

  | ASN1Alias alias ->
    let header_constraint = split_header _loc alias.aaheader in
    let dump_content = dump_fun_of_ptype _loc alias.aatype in
    let meta_f_name = if alias.aalist then "produce_der_seqof" else "produce_der_object" in
    let meta_f = exp_qname _loc (Some "Asn1Engine") meta_f_name in
    [ <:expr< $meta_f$ $header_constraint$ $dump_content$ buf $lid:c.name$ >> ]

  | ASN1Union union ->
    let mk_case (_loc, cons, (p, t)) =
      <:match_case< ( $ <:patt< $uid:cons$ >> $  x ) ->
      $ <:expr< Asn1Engine.produce_der_object $expr_of_pat p$ $dump_fun_of_ptype _loc t$ buf x >> $ >>
    and last_case =
      <:match_case< ( $ <:patt< $uid:union.unparsed_constr$ >> $  o ) -> Asn1PTypes.dump_der_object buf o >>
    in
    let cases = (List.map mk_case union.uchoices)@[last_case] in
    [ <:expr< (fun [ $list:cases$ ]) $lid:c.name$ >> ]

  in
  List.map (mk_multiple_args_fun _loc ("dump_" ^ c.name) ((keep_dump_params c.params)@["buf"; c.name])) body


let mk_exact_dump_fun _loc c =
  let partial_params = List.map (fun p -> <:expr< $lid:p$ >>) (keep_dump_params c.params)
  and params = (keep_dump_params c.params)@[c.name] in
  let dump_fun = apply_exprs _loc (exp_qname _loc None ("dump_" ^ c.name)) partial_params in
  let body = <:expr< Parsifal.exact_dump $dump_fun$ $lid:c.name$ >> in
  [ mk_multiple_args_fun _loc ("exact_dump_" ^ c.name) params body ]



(**********************)
(* VALUE_OF FUNCTIONS *)
(**********************)

let rec value_of_fun_of_ptype _loc t =
  match t with
  | PT_Empty -> Loc.raise _loc (Failure "Empty types should never be concretized")
  | PT_Custom (m, n, _) -> exp_qname _loc m ("value_of_" ^ n)
  | PT_CustomContainer (m, n, _, subtype) ->
     <:expr< $exp_qname _loc m ("value_of_" ^ n)$ $value_of_fun_of_ptype _loc subtype$ >>


let mk_value_of_fun _loc c =
  let body = match c.construction with
  | Enum _ ->
    let ioe = <:expr< $lid:"int_of_" ^ c.name$ >>
    and soe = <:expr< $lid:"string_of_" ^ c.name$ >> in
    <:expr< Parsifal.value_of_enum $soe$ $ioe$ $lid:c.name$ >>

  | Struct fields ->
    let value_of_one_field (_loc, n, t, attr) =
      let field_name = if attr = ParseField then "@" ^ n else n in
      let raw_f = value_of_fun_of_ptype _loc t in
      let f = if attr = Optional then <:expr< Parsifal.try_value_of $raw_f$ >> else raw_f in
      <:expr< ($str:field_name$, $f$ $lid:c.name$.$lid:n$) >>
    in
    let name_field = <:expr< ("@name", Parsifal.VString ($str:c.name$, False)) >> in
    let fields_expr = exp_of_list _loc (List.map value_of_one_field (keep_built_fields fields)) in
    <:expr< Parsifal.VRecord ($uid:"::"$ $name_field$ $fields_expr$) >>

  | Union union
  | ASN1Union union ->
    let mk_case case = match case, c <.> NoAlias with
      | (_loc, cons, (_, PT_Empty)), false ->
        <:match_case< $ <:patt< $uid:cons$ >> $ -> Parsifal.VAlias ( $str:cons$, Parsifal.VUnit ) >>
      | (_loc, cons, (_, PT_Empty)), true ->
        <:match_case< $ <:patt< $uid:cons$ >> $ -> Parsifal.VUnit >>
      | (_loc, cons, (_, t)), false ->
        <:match_case< ( $ <:patt< $uid:cons$ >> $  x ) ->
        $ <:expr< Parsifal.VAlias ( $str:cons$, $value_of_fun_of_ptype _loc t$ x ) >> $ >>
      | (_loc, cons, (_, t)), true ->
        <:match_case< ( $ <:patt< $uid:cons$ >> $  x ) -> $ <:expr< $value_of_fun_of_ptype _loc t$ x >> $ >>
    in
    let last_case =
      <:match_case< ( $ <:patt< $uid:union.unparsed_constr$ >> $  x ) ->
      $ <:expr< Parsifal.VUnparsed ($value_of_fun_of_ptype _loc union.unparsed_type$ x) >> $ >>
    in
    let cases = (List.map mk_case (keep_unique_cons union.uchoices))@[last_case] in
    <:expr< (fun [ $list:cases$ ]) $lid:c.name$ >>

  | Alias atype ->
    <:expr< Parsifal.VAlias ( $str:c.name$, $value_of_fun_of_ptype _loc atype$ $lid:c.name$ ) >>

  | ASN1Alias alias ->
    let value_of_content = value_of_fun_of_ptype _loc alias.aatype in
    if alias.aalist
    then <:expr< Parsifal.VAlias ( $str:c.name$, BasePTypes.value_of_list $value_of_content$ $lid:c.name$ ) >>
    else <:expr< Parsifal.VAlias ( $str:c.name$, $value_of_content$ $lid:c.name$ ) >>

  in [ mk_multiple_args_fun _loc ("value_of_" ^ c.name) [c.name] body ]


(************************)
(* Camlp4 grammar rules *)
(************************)


(* Useful functions *)
let check_options construction options =
  let rec aux opts = match construction, opts with
    | Enum _, (_loc, Param _)::_ ->
      Loc.raise _loc (Failure "params are not allowed for an enum.")

    | _, (_, Param l)::r ->
      let os, ps = aux r in
      os, l::ps

    | (Enum _|Struct _|Alias _|ASN1Alias _), (_loc, EnrichByDefault)::_ ->
      Loc.raise _loc (Failure "enrich is only allowed for unions.")
    | (Enum _|Struct _|Alias _|ASN1Alias _), (_loc, NoAlias)::_ ->
      Loc.raise _loc (Failure "noalias is only allowed for unions.")
    | (Enum _|Struct _|Alias _|ASN1Alias _), (_loc, ExhaustiveChoices)::_ ->
      Loc.raise _loc (Failure "exhaustive is only allowed for unions.")

    | Enum _, (_, LittleEndian)::r ->
      let os, ps = aux r in
      LittleEndian::os, ps
    | _, (_loc, LittleEndian)::_ ->
      Loc.raise _loc (Failure "little_endian is only allowed for enums.")

    | _, (_, o)::r ->
      let os, ps = aux r in
      o::os, ps
    | _, [] -> [], []
  in
  let o, p = aux options in
  o, List.concat p

let meta_mk option then_fun else_fun _loc c =
  if c <.> option
  then then_fun _loc c
  else else_fun _loc c

let mk_nothing _ _ = []

let mk_parsifal_construction _loc name raw_opts specific_descr =
  let options, raw_params = check_options specific_descr raw_opts in
  let params = match specific_descr with
    | Union _ -> raw_params@[ParseParam, "discriminator"]
    | _ -> raw_params
  in
  let pc = { name = lid_of_ident name;
             options = options;
             params = params;
             construction = specific_descr }
  and funs = [ mk_decls; mk_type; mk_specific_funs;
               meta_mk NoParse mk_nothing mk_parse_fun;
               meta_mk ExactParser mk_exact_parse_fun mk_nothing;
               meta_mk NoDump mk_nothing mk_dump_fun;
               meta_mk ExactParser mk_exact_dump_fun mk_nothing;
               meta_mk NoValueOf mk_nothing mk_value_of_fun ] in
  mk_sequence _loc (List.concat (List.map (fun f -> f _loc pc) funs))


let mk_parse_param e accu = (ParseParam, e)::accu
let mk_both_param e accu = (BothParam, e)::accu
let mk_context_param e accu = match e with
  | ExId (_, IdLid (_loc, p)) ->
    ( ParseParam, <:expr< $lid:"parse_" ^  p$ >> )::
    ( DumpParam, <:expr< $lid:"dump_" ^  p$ >> )::accu
  | e -> Loc.raise (loc_of_expr e) (Failure "Context parameters should be lowercase identifiers")

let extract_param_type default_param raw_param accu = match raw_param with
  | <:expr< $uid:"DUMP"$ $e$ >> -> (DumpParam, e)::accu
  | <:expr< $uid:"BOTH"$ $e$ >> -> (BothParam, e)::accu
  | <:expr< $uid:"PARSE"$ $e$ >> -> (ParseParam, e)::accu
  | <:expr< $uid:"CONTEXT"$ $e$ >> -> mk_context_param e accu
  | e -> default_param e accu

let mk_evanescent_varname =
  let evanescent_ref = ref 0 in
  fun () ->
    incr evanescent_ref;
    Printf.sprintf "_evanescent_var_%4.4d" !evanescent_ref


(* TODO: Work on better errors *)

EXTEND Gram
  GLOBAL: str_item;

  option_list: [[
    -> []
  | "["; "]" -> []
  | "["; _opts = expr; "]" -> opts_of_seq_expr _opts
  ]];

  enum_unknown_behaviour: [[
    "Exception" -> Exception
  | "UnknownVal"; x = ident -> UnknownVal (uid_of_ident x)
  ]];

  ptype_decorator: [[
    "{"; e = expr; "}"; next_decorator = ptype_decorator ->
    (List.fold_right (extract_param_type mk_context_param) (list_of_sem_expr e) [])@next_decorator
  | "["; e = expr; "]"; next_decorator = ptype_decorator ->
    (List.fold_right (extract_param_type mk_both_param) (list_of_sem_expr e) [])@next_decorator
  | "("; e = expr; ")"; next_decorator = ptype_decorator ->
    (List.fold_right (extract_param_type mk_parse_param) (list_of_sem_expr e) [])@next_decorator
  | -> []
  ]];

  ptype: [[
    "("; t = SELF; ")" -> t
  | type_name = ident; e = ptype_decorator; t = OPT [ "of"; _t = ptype -> _t ] ->
    ptype_of_ident type_name e t
  ]];

  struct_field: [[
    "parse_checkpoint"; ":"; field = ptype ->
    (_loc, mk_evanescent_varname (), field, ParseCheckpoint)
  | "dump_checkpoint"; ":"; field = ptype ->
    (_loc, mk_evanescent_varname (), field, DumpCheckpoint)
  | attr = OPT [
      "optional" -> Optional;
    | "parse_checkpoint" -> ParseCheckpoint;
    | "dump_checkpoint" -> DumpCheckpoint;
    | "parse_field" -> ParseField
    ]; name = ident; ":"; field = ptype  ->
    begin
      match attr with
      | Some a -> (_loc, lid_of_ident name, field, a)
      | None -> (_loc, lid_of_ident name, field, NoFieldAttr)
    end
  | "dump_arg"; name = ident ->
    (_loc, lid_of_ident name, PT_Empty, DumpArg)
  ]];

  struct_fields: [[
    f = struct_field; ";"; fs = struct_fields -> f::fs
  | f = struct_field -> [f]
  | -> []
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
    "{"; fields = struct_fields; "}" ->
    mk_parsifal_construction _loc name raw_opts (Struct fields)

  | "union"; name = ident; raw_opts = option_list;
    "("; u_b = union_unparsed_behaviour; ")";
    "="; choices = LIST1 union_choice ->
    let union_descr = Union {
      uchoices = choices;
      unparsed_constr = fst u_b;
      unparsed_type = pop_option (PT_Custom (Some "BasePTypes", "rem_binstring", [])) (snd u_b);
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
    let content_name = (lid_of_ident name) ^ "_content" in
    let aa_descr = ASN1Alias {
      aalist = false;
      aaheader = (Universal "T_Sequence", true);
      aatype = (PT_Custom (None, content_name, []))
    } in
    mk_parsifal_construction _loc name raw_opts aa_descr      

  | "asn1_struct"; name = ident; raw_opts = option_list; "=";
    "{"; fields = struct_fields; "}" ->
    let content_name = (lid_of_ident name) ^ "_content" in
    let content_ident = <:ident< $lid:content_name$ >> in
    let struct_funs = mk_parsifal_construction _loc content_ident raw_opts (Struct fields) in
    let aa_descr = ASN1Alias {
      aalist = false;
      aaheader = (Universal "T_Sequence", true);
      aatype = (PT_Custom (None, content_name, []))
    } in
    let alias_funs = mk_parsifal_construction _loc name raw_opts aa_descr in
    mk_sequence _loc [struct_funs; alias_funs]

  | "asn1_union"; name = ident; raw_opts = option_list;
    "("; u_c = ident; ")";
    "="; choices = LIST1 union_choice ->
    let asn1_union_descr = ASN1Union {
      uchoices = choices;
      unparsed_constr = uid_of_ident u_c;
      unparsed_type = PT_Custom (Some "Asn1PTypes", "der_object", []);
    } in
    mk_parsifal_construction _loc name raw_opts asn1_union_descr

  ]];
END
;;
