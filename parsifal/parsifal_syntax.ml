open Camlp4
open Camlp4.PreCast
open Camlp4.PreCast.Ast
open Syntax


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


(* let uid_of_expr = function *)
(*   | <:expr< $uid:id$ >> -> id *)
(*   | e -> Loc.raise (loc_of_expr e) (Failure "uppercase identifier expected") *)

(* let exp_true _loc = <:expr< $uid:"True"$ >> *)
(* let exp_false _loc = <:expr< $uid:"False"$ >> *)
(* let exp_bool _loc b = if b then exp_true _loc else exp_false _loc *)

(* let rec exp_of_list _loc = function *)
(*   | [] -> <:expr< $uid:"[]"$ >> *)
(*   | e::r -> <:expr< $uid:"::"$ $e$ $exp_of_list _loc r$ >> *)


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


let mk_pm_fun _loc fname cases =
  let mk_case (p, e) = <:match_case< $p$ -> $e$ >> in
  let cases = List.map mk_case cases in
  let body = <:expr< fun [ $list:cases$ ] >>
  and fun_name = <:patt< $lid:fname$ >> in
  let bindings = <:binding< $pat:fun_name$ = $exp:body$ >> in
  [ <:str_item< value $bindings$ >> ]


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
  | ExactParser
  | EnrichByDefault
  | ExhaustiveChoices
  | Param of string list

type parsifal_construction =
  | Enum
  | Struct
  | Union
  | Alias
  | ASN1Alias

let check_options construction options =
  let rec aux opts = match construction, opts with
    | Enum, (_loc, ExactParser)::_ ->
      Loc.raise _loc (Failure "with_exact/top is not allowed for an enum.")
    | Enum, (_loc, Param _)::_ ->
      Loc.raise _loc (Failure "params are not allowed for an enum.")
    | (Enum|Struct|Alias|ASN1Alias), (_loc, EnrichByDefault)::_ ->
      Loc.raise _loc (Failure "enrich is only allowed for unions.")
    | (Enum|Struct|Alias|ASN1Alias), (_loc, ExhaustiveChoices)::_ ->      
      Loc.raise _loc (Failure "exhaustive is only allowed for unions.")
    | _, (_, o)::r -> o::(aux r)
    | _, [] -> []
  in aux options

let mk_params opts =
  let rec _mk_params = function
    | [] -> []
    | (Param l)::r -> l::(_mk_params r)
    | _::r -> _mk_params r
  in List.concat (_mk_params opts)


(* Enums *)

type enum_unknown_behaviour =
  | UnknownVal of string
  | Exception of string

type enum_description = {
  ename : string;
  size : int;
  echoices : (Loc.t * string * string * string) list;
  unknown_behaviour : enum_unknown_behaviour;
  edo_lwt : bool;
}


(* PTypes *)

type field_len =
  | ExprLen of expr    (* size in bytes of the field *)
  | VarLen of string   (* name of the integer type used *)
  | Remaining

type field_type =
  | FT_Empty
  | FT_Char
  | FT_Int of string                        (* name of the integer type *)
  | FT_String of field_len * bool
  | FT_List of field_len * field_type
  | FT_Container of field_len * field_type  (* the string corresponds to the integer type for the field length *)
  | FT_Custom of (string option) * string * expr list  (* the expr list is the list of args to apply to parse funs *)
  | FT_CheckFunction of (string option) * string * expr list * bool  (* the last boolean is set if the function is in fact a reference *)


(* Records *)

type record_description = {
  rname : ident;
  fields : (Loc.t * string * field_type * bool) list;
  rdo_lwt : bool;
  rdo_exact : bool;
  rparse_params : string list;
}


(* Unions *)

type union_description = {
  uname : ident;
  uchoices : (Loc.t * patt * string * field_type) list;   (* loc, discriminating value, constructor, subtype *)
  unparsed_constr : string;
  unparsed_type : field_type;
  udo_lwt : bool;
  udo_exact : bool;
  uenrich : bool;
  uexhaustive : bool;
  uparse_params : string list;
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
    | <:expr< $lid:"param"$ $e$ >>  -> [_loc, Param (List.map lid_of_expr (list_of_com_expr e))]
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



(*****************************)
(* OCaml definitions         *)
(*   ParsifalSyntax -> OCaml *)
(*****************************)

(* Enum exception *)

let mk_enum_exception _loc enum = match enum with
  | {unknown_behaviour = Exception e} ->
    [ <:str_item< exception  $typ:<:ctyp< $uid:e$ >>$  >> ]
  | _ -> []


(* Enum type *)

let mk_enum_type _loc enum =
  let ctors = List.map (fun (_loc, _, n, _) -> <:ctyp< $uid:n$ >>) enum.echoices in
  let suffix_choice = match enum.unknown_behaviour with
    | UnknownVal v -> [ <:ctyp< $ <:ctyp< $uid:v$ >> $ of int >> ]
    | _ -> []
  in
  let ctyp_ctors = ctors@suffix_choice in
  [ <:str_item< type $lid:enum.ename$ = [ $list:ctyp_ctors$ ] >> ]



(* Enum primitive functions *)

let mk_string_of_enum _loc enum =
  let mk_case (_loc, _, n, d) = <:patt< $uid:n$ >>, <:expr< $str:d$ >> in
  let _cases = List.map mk_case enum.echoices in
  let cases = match enum.unknown_behaviour with
    | UnknownVal v ->
      let p = <:patt< $ <:patt< $uid:v$ >> $ $ <:patt< $lid:"i"$ >> $ >>
      and e = <:expr< $str:"Unknown " ^ enum.ename ^ " ("$ ^ (string_of_int i) ^ $str:")"$ >>
      in _cases@[p, e]
    | _ -> _cases
  and fname = "string_of_" ^ enum.ename in
  mk_pm_fun _loc fname cases


let mk_int_of_enum _loc enum =
  let mk_case (_loc, v, n, _) = <:patt< $uid:n$ >>, <:expr< $int:v$ >> in
  let _cases = List.map mk_case enum.echoices in
  let cases = match enum.unknown_behaviour with
    | UnknownVal v ->
      let p = <:patt< $ <:patt< $uid:v$ >> $ $ <:patt< $lid:"i"$ >> $ >>
      and e = <:expr< $lid:"i"$ >>
      in _cases@[p, e]
    | _ -> _cases
  and fname = "int_of_" ^ enum.ename in
  mk_pm_fun _loc fname cases


let mk_enum_of_int _loc enum =
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
  and fname = enum.ename ^ "_of_int" in
  mk_pm_fun _loc fname cases


let mk_enum_of_string _loc enum =
  let mk_case (_loc, _, n, d) = <:patt< $str:d$ >>, <:expr< $uid:n$ >> in
  let _cases = List.map mk_case enum.echoices in
  let last_p = <:patt< $lid:"s"$ >>
  and eoi = <:expr< $lid:enum.ename ^ "_of_int"$ >> in
  let last_e = <:expr< $eoi$  (int_of_string s) >> in
  let cases = _cases@[last_p, last_e]
  and fname = enum.ename ^ "_of_string" in
  mk_pm_fun _loc fname cases






(* Parsing functions *)

let mk_enum_parse_fun _loc enum = 
  if enum.size mod 8 = 0 then begin
    let fname = "parse_" ^ enum.ename
    (* TODO: factor this line with the mk_ocaml_parse_fun? *)
    and parse_int_fun = exp_qname _loc (Some "Parsifal") ("parse_uint" ^ (string_of_int enum.size))
    and eoi = <:expr< $lid:enum.ename ^ "_of_int"$ >> in
    let body = <:expr< $eoi$ ($parse_int_fun$ input) >> in
    [ mk_multiple_args_fun _loc fname ["input"] body ]
  end else []


(* Lwt Parsing functions *)

let mk_enum_lwt_parse_fun _loc enum =
  if enum.edo_lwt && enum.size mod 8 = 0 then begin
    let fname = "lwt_parse_" ^ enum.ename
    (* TODO: factor this line with the mk_ocaml_parse_fun? *)
    and lwt_parse_int_fun = exp_qname _loc (Some "Parsifal") ("lwt_parse_uint" ^ (string_of_int enum.size))
    and eoi = <:expr< $lid:enum.ename ^ "_of_int"$ >> in
    let body = <:expr< Lwt.bind ($lwt_parse_int_fun$ input) (Lwt.wrap1 $eoi$) >> in
    [ mk_multiple_args_fun _loc fname ["input"] body ]
  end else []


(* Dumping functions *)

let mk_enum_dump_fun _loc enum =
  if enum.size mod 8 = 0 then begin
    let fname = "dump_" ^ enum.ename
    (* TODO: factor this line with the mk_ocaml_parse_fun? *)
    and dump_int_fun = exp_qname _loc (Some "Parsifal") ("dump_uint" ^ (string_of_int enum.size))
    and ioe = <:expr< $lid:"int_of_" ^ enum.ename$ >> in
    let body = <:expr< $dump_int_fun$ ($ioe$ $lid:enum.ename$) >> in
    [ mk_multiple_args_fun _loc fname [enum.ename] body ]
  end else []


(* Printing functions *)

let mk_enum_print_fun _loc enum =
  let fname = "print_" ^ enum.ename
  (* TODO: factor this line with the mk_ocaml_parse_fun? *)
  and print_fun = exp_qname _loc (Some "Parsifal") ("print_enum")
  and ioe = <:expr< $lid:"int_of_" ^ enum.ename$ >>
  and soe = <:expr< $lid:"string_of_" ^ enum.ename$ >> in
  let body = <:expr< $print_fun$ $soe$ $ioe$ $int:string_of_int (enum.size / 4)$
              ~indent:indent ~name:name $lid:enum.ename$ >>
  and optargs = ["indent", <:expr< $str:""$ >>; "name", <:expr< $str:enum.ename$ >>] in
  [ mk_multiple_args_fun _loc fname [enum.ename] ~optargs:optargs body ]




(************************)
(* Camlp4 grammar rules *)
(************************)

let mk_str_items funs _loc x =
  let _apply f = f _loc x in
  let rec mk_sequence = function
    | [] -> <:str_item< >>
    | [si] -> <:str_item< $si$ >>
    | si::r -> <:str_item< $si$; $mk_sequence r$ >>
  in
  mk_sequence (List.concat (List.map _apply funs))


EXTEND Gram
  GLOBAL: str_item;

  unknown_behaviour: [[
    "Exception"; x = ident -> Exception (uid_of_ident x)
  | "UnknownVal"; x = ident -> UnknownVal (uid_of_ident x)
  ]];

  option_list: [[
    -> []
  | "["; "]" -> []
  | "["; _opts = expr; "]" -> opts_of_seq_expr _opts
  ]];




  str_item: [[
    "enum"; enum_name = ident; opts = option_list;
    "("; sz = INT; ","; u_b = unknown_behaviour; ")";
    "="; _choices = match_case ->
    let choices = choices_of_match_cases _choices
    and options = check_options Enum opts in
    let enum_descr = {
      ename = lid_of_ident enum_name;
      size = int_of_string sz;
      echoices = choices;
      unknown_behaviour = u_b;
      edo_lwt = List.mem DoLwt options
    } in
    let fns = [mk_enum_exception; mk_enum_type; mk_string_of_enum;
	       mk_int_of_enum; mk_enum_of_int; mk_enum_of_string;
	       mk_enum_parse_fun; mk_enum_lwt_parse_fun;
	       mk_enum_dump_fun; mk_enum_print_fun] in
    mk_str_items fns _loc enum_descr
  ]];


  (* field_type_opt_param: [[ *)
  (*   "("; e = expr; ")" -> ExprDec e *)
  (* | "["; e = expr; "]" -> VarLenDec e *)
  (* | -> NoDec *)
  (* ]]; *)

  (* field_type_d: [[ *)
  (*   "("; t = SELF; ")" -> t *)
  (* | type_name = ident; e = field_type_opt_param; t = OPT [ "of"; _t = field_type_d -> _t ] -> *)
  (*   field_type_of_ident type_name e t *)
  (* ]]; *)

  (* field_desc: [[ *)
  (*   optional = OPT [ "optional" -> () ]; name = ident; ":"; field = field_type_d  -> *)
  (*   (_loc, lid_of_ident name, field, optional != None) *)
  (* ]]; *)

  (* choice_desc: [[ *)
  (*   "|"; discr_val = patt; "->"; constructor = ident; "of"; t = field_type_d -> *)
  (*     (_loc, discr_val, uid_of_ident constructor, t) *)
  (* | "|"; discr_val = patt; "->"; constructor = ident -> *)
  (*     (_loc, discr_val, uid_of_ident constructor, FT_Empty) *)
  (* ]]; *)

  (* unparsed_behavior: [[ *)
  (*   unparsed_const = ident -> (uid_of_ident unparsed_const, FT_String (Remaining, true)) *)
  (* | unparsed_const = ident; "of"; unparsed_type = field_type_d -> (uid_of_ident unparsed_const, unparsed_type) *)
  (* ]]; *)

  (* str_item: [[ *)
  (*   "struct"; record_name = ident; opts = option_list; "="; *)
  (*            "{"; fields = LIST1 field_desc SEP ";"; OPT [ ";" -> () ]; "}" -> *)
  (*     let record = mk_record_desc (lid_of_ident record_name) fields opts in *)
  (*     let si1 = mk_record_type _loc record *)
  (*     and si2 = mk_record_parse_fun _loc record *)
  (*     and si3 = *)
  (* 	if record.rdo_lwt *)
  (* 	then mk_record_lwt_parse_fun _loc record *)
  (* 	else <:str_item< >> *)
  (*     and si4 = *)
  (* 	if record.rdo_exact *)
  (* 	then mk_exact_parse_fun _loc record.rname record.rparse_params *)
  (* 	else <:str_item< >> *)
  (*     and si5 = mk_record_dump_fun _loc record *)
  (*     and si6 = mk_record_print_fun _loc record *)
  (*     in *)
  (*     <:str_item< $si1$; $si2$; $si3$; $si4$; $si5$; $si6$ >> *)

  (* | "union"; union_name = ident; *)
  (*     "("; unparsed_behavior = unparsed_behavior; ","; *)
  (*          opts = option_list; ")"; "=";  *)
  (*     choices = LIST1 choice_desc  -> *)
  (*     let union = mk_union_desc (lid_of_ident union_name) choices unparsed_behavior opts in *)
  (*     let si0 = *)
  (* 	<:str_item< value $ <:binding< $pat:pat_lid _loc ("enrich_" ^ union.uname)$ = *)
  (*                                      $exp: <:expr< ref $exp_bool _loc union.uenrich$ >> $ >> $ >> *)
  (*     and si1 = mk_union_type _loc union *)
  (*     and si2 = mk_union_parse_fun _loc union *)
  (*     and si3 = *)
  (*       if union.udo_lwt *)
  (* 	then mk_union_lwt_parse_fun _loc union *)
  (* 	else <:str_item< >> *)
  (*     and si4 = *)
  (* 	if union.udo_exact *)
  (* 	then mk_exact_parse_fun _loc union.uname union.uparse_params *)
  (* 	else <:str_item< >> *)
  (*     and si5 = mk_union_dump_fun _loc union *)
  (*     and si6 = mk_union_print_fun _loc union *)
  (*     in *)
  (*     <:str_item< $si0$; $si1$; $si2$; $si3$; $si4$; $si5$; $si6$ >> *)
  (* ]]; *)
END
;;
