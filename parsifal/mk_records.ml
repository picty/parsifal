
let keep_unique_cons union =
  let rec _keep_unique_cons names accu = function
  | [] -> List.rev accu
  | ((_, _, n, _) as c)::r  ->
    if List.mem n names
    then _keep_unique_cons names accu r
    else _keep_unique_cons (n::names) (c::accu) r
  in _keep_unique_cons [] [] union.choices


(* To-be-processed file parsing *)

type decorator_type = NoDec | ExprDec of expr | VarLenDec of expr

let rec field_type_of_ident name decorator subtype =
  match name, decorator, subtype with
    | <:ident< $lid:"empty"$ >>,  NoDec, None -> FT_Empty
    | <:ident< $lid:"char"$ >>,   NoDec, None -> FT_Char
    | <:ident< $lid:("uint8"|"uint16"|"uint24"|"uint32" as int_t)$ >>, NoDec, None -> FT_Int int_t

    | <:ident< $lid:"list"$ >>,   NoDec, Some t ->
      FT_List (Remaining, t)
    | <:ident< $lid:"list"$ >>,   ExprDec e, Some t ->
      FT_List (ExprLen e, t)
    | <:ident< $lid:"list"$ >>,   VarLenDec <:expr< $lid:("uint8"|"uint16"|"uint24"|"uint32" as int_t)$ >>, Some t ->
      FT_List (VarLen int_t, t)
    | <:ident< $lid:"list"$ >> as i,   _, _ ->
      Loc.raise (loc_of_ident i) (Failure "invalid list type")

    | <:ident< $lid:"container"$ >>, ExprDec e, Some t ->
      FT_Container (ExprLen e, t)
    | <:ident< $lid:"container"$ >>, VarLenDec <:expr< $lid:("uint8"|"uint16"|"uint24"|"uint32" as int_t)$ >>, Some t ->
      FT_Container (VarLen int_t, t)
    | <:ident< $lid:"container"$ >> as i, _, _ ->
      Loc.raise (loc_of_ident i) (Failure "invalid container type")

    | <:ident< $lid:"string"$ >>,    NoDec, None-> FT_String (Remaining, false)
    | <:ident< $lid:"binstring"$ >>, NoDec, None -> FT_String (Remaining, true)
    | <:ident< $lid:"string"$ >>,    ExprDec e, None ->
      FT_String (ExprLen e, false)
    | <:ident< $lid:"binstring"$ >>, ExprDec e, None ->
      FT_String (ExprLen e, true)
    | <:ident< $lid:"string"$ >>,    VarLenDec <:expr< $lid:("uint8"|"uint16"|"uint24"|"uint32" as int_t)$ >>, None ->
      FT_String (VarLen int_t, false)
    | <:ident< $lid:"binstring"$ >>, VarLenDec <:expr< $lid:("uint8"|"uint16"|"uint24"|"uint32" as int_t)$ >>, None ->
      FT_String (VarLen int_t, true)
    | <:ident< $lid:("string" | "binstring")$ >> as i, _, _ ->
      Loc.raise (loc_of_ident i) (Failure "invalid string type")

    | <:ident< $lid:"check"$ >>,      NoDec, Some (FT_Custom (m, n, args)) ->
      FT_CheckFunction (m, n, args, false)
    | <:ident< $lid:"checkref"$ >>,   NoDec, Some (FT_Custom (m, n, args)) ->
      FT_CheckFunction (m, n, args, true)
    | <:ident< $lid:("check"|"checkref")$ >> as i, _, _ ->
      Loc.raise (loc_of_ident i) (Failure "invalid check declaration")

    | <:ident< $lid:custom_t$ >>, NoDec, None ->
      FT_Custom (None, custom_t, [])
    | <:ident< $lid:custom_t$ >>, ExprDec e, None ->
      FT_Custom (None, custom_t, list_of_sem_expr e)
    | <:ident< $uid:module_name$.$lid:custom_t$ >>, NoDec, None ->
      FT_Custom (Some module_name, custom_t, [])
    | <:ident< $uid:module_name$.$lid:custom_t$ >>, ExprDec e, None ->
      FT_Custom (Some module_name, custom_t, list_of_sem_expr e)

    | i, _, _ -> Loc.raise (loc_of_ident i) (Failure "invalid identifier for a type")


(* Type creation *)

let rec _ocaml_type_of_field_type _loc = function
  | FT_Empty
  | FT_CheckFunction _ -> <:ctyp< $lid:"unit"$ >>
  | FT_Char -> <:ctyp< $lid:"char"$ >>
  | FT_Int _ -> <:ctyp< $lid:"int"$ >>
  | FT_String _ -> <:ctyp< $lid:"string"$ >>
  | FT_List (_, subtype) -> <:ctyp< list $_ocaml_type_of_field_type _loc subtype$ >>
  | FT_Container (_, subtype) -> _ocaml_type_of_field_type _loc subtype
  | FT_Custom (None, n, _) -> <:ctyp< $lid:n$ >>
  | FT_Custom (Some m, n, _) -> <:ctyp< $uid:m$.$lid:n$ >>


let ocaml_type_of_field_type _loc t opt =
  let real_t = _ocaml_type_of_field_type _loc t in
  if opt then <:ctyp< option $real_t$ >> else real_t

let rec remove_dummy_fields = function
  | [] -> []
  | (_, _, FT_Empty, _)::r | (_, _, FT_CheckFunction _, _)::r -> remove_dummy_fields r
  | f::r -> f::(remove_dummy_fields r)

let mk_record_type _loc record =
  let mk_line (_loc, n, t, opt) = <:ctyp< $lid:n$ : $ocaml_type_of_field_type _loc t opt$ >> in
  let ctyp_fields = List.map mk_line (remove_dummy_fields record.fields) in
  <:str_item< type $lid:record.rname$ = { $list:ctyp_fields$ } >>

let mk_union_type _loc union =
  let rec mk_ctors = function
    | [] ->
      [ <:ctyp< $ctyp_uid _loc union.unparsed_constr$ of
	        $ocaml_type_of_field_type _loc union.unparsed_type false$ >> ]
    | (_loc, _, n, FT_Empty)::r ->	
      (ctyp_uid _loc n)::(mk_ctors r)
    | (_loc, _, n, t)::r ->	
      ( <:ctyp< $ctyp_uid _loc n$ of
                $ocaml_type_of_field_type _loc t false$ >> )::(mk_ctors r)
  in

  let ctyp_ctors = mk_ctors (keep_unique_cons union) in
  <:str_item< type $lid:union.uname$ = [ $list:ctyp_ctors$ ] >>


(* Parse functions *)

let rec fun_of_field_type (prefix, module_prefix) _loc name t =
  let mk_pf fname = <:expr< $uid:module_prefix$.$lid:prefix ^ fname$ >> in
  match t with
    | FT_Empty -> mk_pf "empty"
    | FT_Char -> mk_pf "char"
    | FT_Int int_t -> mk_pf int_t

    | FT_String (ExprLen e, _) -> <:expr< $mk_pf "string"$ $e$ >>
    | FT_String (VarLen int_t, _) ->
      <:expr< $mk_pf "varlen_string"$ $exp_str _loc name$ $mk_pf int_t$ >>
    | FT_String (Remaining, _) -> mk_pf "rem_string"

    | FT_List (ExprLen e, subtype) ->
      <:expr< $mk_pf "list"$ $e$
              $fun_of_field_type (prefix, module_prefix) _loc name subtype$ >>
    | FT_List (VarLen int_t, subtype) ->
      <:expr< $mk_pf "varlen_list"$ $exp_str _loc name$ $mk_pf int_t$
              $fun_of_field_type ("parse_", "ParsingEngine") _loc name subtype$ >>
    | FT_List (Remaining, subtype) ->
      <:expr< $mk_pf "rem_list"$
              $fun_of_field_type ("parse_", "ParsingEngine") _loc name subtype$ >>
    | FT_Container (ExprLen e, subtype) ->
      <:expr< $mk_pf "container"$ $exp_str _loc name$ $e$
              $fun_of_field_type ("parse_", "ParsingEngine") _loc name subtype$ >>
    | FT_Container (VarLen int_t, subtype) ->
      <:expr< $mk_pf "varlen_container"$ $exp_str _loc name$ $mk_pf int_t$
              $fun_of_field_type ("parse_", "ParsingEngine") _loc name subtype$ >>
    (* TODO: the following case should never happen *)
    | FT_Container (Remaining, subtype) ->
      fun_of_field_type ("parse_", "ParsingEngine") _loc name subtype

    | FT_Custom (m, n, e) -> apply_exprs _loc (exp_qname _loc m (prefix ^ n)) e
    | FT_CheckFunction (m, n, e, false) -> apply_exprs _loc (exp_qname _loc m (prefix ^ n)) e
    | FT_CheckFunction (m, n, e, true) -> apply_exprs _loc ( <:expr< ! $exp_qname _loc m (prefix ^ n)$ >> ) e


let mk_record_parse_fun _loc record =
  let rec mk_body = function
    | [] ->
      let field_assigns = List.map (fun (_loc, n, _, _) ->
	<:rec_binding< $lid:n$ = $exp:exp_lid _loc n$ >> ) (remove_dummy_fields record.fields)
      in <:expr< { $list:field_assigns$ } >>
    | (_loc, n, t, false)::r ->
      let tmp = mk_body r in
      <:expr< let $lid:n$ = $fun_of_field_type ("parse_", "ParsingEngine") _loc n t$ input in $tmp$ >>
    | (_loc, n, t, true)::r ->
      let tmp = mk_body r in
      <:expr< let $lid:n$ = ParsingEngine.try_parse $fun_of_field_type ("parse_", "ParsingEngine") _loc n t$ input in $tmp$ >>
  in

  let body = mk_body record.fields in
  let params = record.rparse_params@["input"] in
  <:str_item< value $mk_multiple_args_fun _loc ("parse_" ^ record.rname) params body$ >>

let mk_record_lwt_parse_fun _loc record =
  let rec mk_body = function
    | [] ->
      let field_assigns = List.map (fun (_loc, n, _, _) ->
	<:rec_binding< $lid:n$ = $exp:exp_lid _loc n$ >> ) (remove_dummy_fields record.fields)
      in <:expr< Lwt.return { $list:field_assigns$ } >>
    | (_loc, n, t, false)::r ->
      let tmp = mk_body r in
      <:expr< Lwt.bind ($fun_of_field_type ("lwt_parse_", "LwtParsingEngine") _loc n t$ input) (fun $lid:n$ -> $tmp$ ) >>
    | (_loc, n, t, true)::r ->
      let tmp = mk_body r in
      <:expr< Lwt.bind (LwtParsingEngine.try_lwt_parse $fun_of_field_type ("lwt_parse_", "LwtParsingEngine") _loc n t$ input) (fun $lid:n$ -> $tmp$ ) >>
  in

  let body = mk_body record.fields in
  let params = record.rparse_params@["input"] in
  <:str_item< value $mk_multiple_args_fun _loc ("lwt_parse_" ^ record.rname) params body$ >>

let mk_union_parse_fun _loc union =
  let mk_case = function
    | (_loc, p, c, FT_Empty) ->
      <:match_case< $p$ -> $exp_uid _loc c$ >>
    | (_loc, p, c, t) ->
      let parse_fun = fun_of_field_type ("parse_", "ParsingEngine") _loc union.uname t in
      <:match_case< $p$ -> $exp_uid _loc c$ ($parse_fun$ input) >>
  and mk_unparsed =
    let parse_fun = fun_of_field_type ("parse_", "ParsingEngine") _loc union.uname union.unparsed_type in
    <:expr< $exp_uid _loc union.unparsed_constr$ ($parse_fun$ input) >>
  in
  let parsed_cases = List.map mk_case union.choices
  and last_case =
    <:match_case< _ -> $mk_unparsed$ >> in
  let cases = if union.uexhaustive then parsed_cases else parsed_cases@[last_case] in
  let body =
    <:expr< if ! $exp_lid _loc ("enrich_" ^ union.uname)$ || enrich
      then match discriminator with [ $list:cases$ ]
      else $mk_unparsed$ >>
  in
  let params = union.uparse_params@["discriminator"; "input"] in
  <:str_item< value $mk_multiple_args_fun _loc ("parse_" ^ union.uname) ~optargs:["enrich", exp_false _loc] params body$ >>

let mk_union_lwt_parse_fun _loc union =
  let mk_case = function
    | (_loc, p, c, FT_Empty) ->
      <:match_case< $p$ -> Lwt.return $exp_uid _loc c$ >>
    | (_loc, p, c, t) ->
      let parse_fun = fun_of_field_type ("lwt_parse_", "LwtParsingEngine") _loc union.uname t in
      <:match_case< $p$ -> Lwt.bind ($parse_fun$ input) (fun v -> Lwt.return ($exp_uid _loc c$ v)) >>
  and mk_unparsed =
    let parse_fun = fun_of_field_type ("lwt_parse_", "LwtParsingEngine") _loc union.uname union.unparsed_type in
    <:expr< Lwt.bind ($parse_fun$ input) (fun v -> Lwt.return ($exp_uid _loc union.unparsed_constr$ v)) >>
  in
  let parsed_cases = List.map mk_case union.choices
  and last_case = <:match_case< _ -> $mk_unparsed$ >> in
  let cases = if union.uexhaustive then parsed_cases else parsed_cases@[last_case] in
  let body =
    <:expr< if ! $exp_lid _loc ("enrich_" ^ union.uname)$ || enrich
      then match discriminator with [ $list:cases$ ]
      else $mk_unparsed$ >>
  in
  let params = union.uparse_params@["discriminator"; "input"] in
  <:str_item< value $mk_multiple_args_fun _loc ("lwt_parse_" ^ union.uname) ~optargs:["enrich", exp_false _loc] params body$ >>


let mk_exact_parse_fun _loc name parse_params =
  let partial_params = List.map (exp_lid _loc) parse_params
  and params = parse_params@["input"] in
  let parse_fun = apply_exprs _loc (exp_qname _loc None ("parse_" ^ name)) partial_params in
  let body = <:expr< ParsingEngine.exact_parse $parse_fun$ input >> in
  <:str_item< value $mk_multiple_args_fun _loc ("exact_parse_" ^ name) params body$ >>



(* Dump function *)

let rec dump_fun_of_field_type _loc t =
  let mk_df fname = <:expr< $uid:"DumpingEngine"$.$lid:fname$ >> in
  match t with
    | FT_Empty | FT_CheckFunction _ -> mk_df "dump_empty"
    | FT_Char -> mk_df "dump_char"
    | FT_Int int_t -> mk_df  ("dump_" ^ int_t)

    | FT_String (VarLen int_t, _) ->
      <:expr< $mk_df "dump_varlen_string"$ $mk_df ("dump_" ^ int_t)$ >>
    | FT_String _ -> mk_df "dump_string"

    | FT_List (VarLen int_t, subtype) ->
      <:expr< $mk_df "dump_varlen_list"$ $mk_df ("dump_" ^ int_t)$ $dump_fun_of_field_type _loc subtype$ >>
    | FT_List (_, subtype) ->
      <:expr< $mk_df "dump_list"$ $dump_fun_of_field_type _loc subtype$ >>
    | FT_Container (VarLen int_t, subtype) ->
      <:expr< $mk_df "dump_container"$ $mk_df ("dump_" ^ int_t)$ $dump_fun_of_field_type _loc subtype$ >>
    | FT_Container (_, subtype) ->
      dump_fun_of_field_type _loc subtype

    | FT_Custom (m, n, _) -> exp_qname _loc m ("dump_" ^ n)


let mk_record_dump_fun _loc record =
  let dump_one_field = function
      (_loc, n, t, false) ->
      <:expr< $dump_fun_of_field_type _loc t$ $lid:record.rname$.$lid:n$ >>
    | (_loc, n, t, true) ->
      <:expr< DumpingEngine.try_dump $dump_fun_of_field_type _loc t$ $lid:record.rname$.$lid:n$ >>
  in
  let fields_dumped_expr = exp_of_list _loc (List.map dump_one_field (remove_dummy_fields record.fields)) in
  let body =
    <:expr< let $lid:"fields_dumped"$ = $fields_dumped_expr$ in
	    String.concat "" fields_dumped >>
  in
  <:str_item< value $ <:binding< $pat:pat_lid _loc ("dump_" ^ record.rname)$ $pat_lid _loc record.rname$ = $exp:body$ >> $ >>

let mk_union_dump_fun _loc union =
  let mk_case = function
    | _loc, _, c, FT_Empty ->
      <:match_case< $pat_uid _loc c$ -> "" >>
    | _loc, _, c, t ->
      <:match_case< ( $pat_uid _loc c$ $pat_lid _loc "x"$ ) -> $ <:expr< $dump_fun_of_field_type _loc t$ x >> $ >>
  in
  let last_case =
    <:match_case< ( $pat_uid _loc union.unparsed_constr$ $pat_lid _loc "x"$ ) ->
                  $ <:expr< $dump_fun_of_field_type _loc union.unparsed_type$ x >> $ >>
  in
  let cases = (List.map mk_case (keep_unique_cons union))@[last_case] in
  let body = <:expr< fun [ $list:cases$ ] >> in
  <:str_item< value $ <:binding< $pat:pat_lid _loc ("dump_" ^ union.uname)$ = $exp:body$ >> $ >>


(* Print function *)

let rec print_fun_of_field_type _loc t =
  let mk_pf fname = <:expr< $uid:"PrintingEngine"$.$lid:fname$ >> in
  match t with
    | FT_Empty | FT_CheckFunction _ -> mk_pf "print_empty"
    | FT_Char -> mk_pf "print_char"
    | FT_Int int_t -> mk_pf  ("print_" ^ int_t)

    | FT_String (_, false) -> mk_pf "print_string"
    | FT_String (_, true) -> mk_pf "print_binstring"

    | FT_List (_, subtype) ->
      <:expr< $mk_pf "print_list"$ $print_fun_of_field_type _loc subtype$ >>
    | FT_Container (_, subtype) -> print_fun_of_field_type _loc subtype
    | FT_Custom (m, n, _) -> exp_qname _loc m ("print_" ^ n)


let mk_record_print_fun _loc record =
  let print_one_field = function
      (_loc, n, t, false) ->
	<:expr< $print_fun_of_field_type _loc t$ ~indent:new_indent ~name:$str:n$ $lid:record.rname$.$lid:n$ >>
    | (_loc, n, t, true) ->
	<:expr< PrintingEngine.try_print $print_fun_of_field_type _loc t$ ~indent:new_indent ~name:$str:n$ $lid:record.rname$.$lid:n$ >>
  in
  let fields_printed_expr = exp_of_list _loc (List.map print_one_field (remove_dummy_fields record.fields)) in
  let body =
    <:expr< let new_indent = indent ^ "  " in
	    let $lid:"fields_printed"$ = $fields_printed_expr$ in
	    indent ^ name ^ " {\\n" ^
	    (String.concat "" fields_printed) ^
	    indent ^ "}\\n" >>
  in
  <:str_item< value $mk_multiple_args_fun _loc ("print_" ^ record.rname) [record.rname]
    ~optargs:(["indent", exp_str _loc ""; "name", exp_str _loc record.rname]) body$ >>

let mk_union_print_fun _loc union =
  let mk_case = function
    | _loc, _, c, FT_Empty ->
      <:match_case< $pat_uid _loc c$ -> PrintingEngine.print_binstring ~indent:indent ~name:name "" >>
    | _loc, _, c, t ->
      <:match_case< ( $pat_uid _loc c$ $pat_lid _loc "x"$ ) ->
                    $ <:expr< $print_fun_of_field_type _loc t$ ~indent:indent ~name:name x >> $ >>
  in
  let last_case =
    <:match_case< ( $pat_uid _loc union.unparsed_constr$ $pat_lid _loc "x"$ ) ->
                  $ <:expr< $print_fun_of_field_type _loc union.unparsed_type$
                                  ~indent:indent ~name:(name ^ "[Unparsed]") x >> $ >>
  in
  let cases = (List.map mk_case (keep_unique_cons union))@[last_case] in
  let body = <:expr< fun [ $list:cases$ ] >> in
  <:str_item< value $mk_multiple_args_fun _loc ("print_" ^ union.uname) []
    ~optargs:(["indent", exp_str _loc ""; "name", exp_str _loc union.uname]) body$ >>

 
