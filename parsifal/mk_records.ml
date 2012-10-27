
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

 
