open Types


type display_opts = {
  raw_display : bool;   (* Display objects as dictionnaries *)
  multiline : bool;     (* Is it multiline? *)
  indent : string;      (* If we are multiline, here is the indent for each level *)
  cur_indent : string;  (* and the current indentation *)
  separator : string;   (* If not multiline, here is the separator *)
}


let rec is_multiline raw v =
  match v with
    | V_List l ->
      let aux accu elt = accu || (is_multiline raw elt) in
      List.fold_left aux false l
    | V_Dict d ->
      let aux _ elt accu = accu || (is_multiline raw elt) in
      Hashtbl.fold aux d false
    | V_Object (_, _, d) ->
      not raw || is_multiline raw (V_Dict d)
    | _ -> false


let rec string_of_value dopts v =
  let constructed_aux o f mk_content content =
    if dopts.multiline then begin
      let new_dopts = {dopts with cur_indent = dopts.cur_indent ^ dopts.indent} in
      let content = mk_content new_dopts content in
      o ^ "\n" ^ (String.concat ("\n" ^ new_dopts.cur_indent) content) ^ dopts.cur_indent ^ f ^ "\n"
    end else begin
      let content = mk_content dopts content in
      o ^ (String.concat dopts.separator content) ^ f
    end
  in
  match v with
    | V_Bool b -> string_of_bool b
    | V_Int i -> string_of_int i
    | V_String s -> "\"" ^ (Common.printable_string s) ^ "\""
    | V_BinaryString s -> "\"" ^ (Common.hexdump s) ^ "\""
    | V_BitString (n, s) -> "\"[" ^ (string_of_int n) ^ "]" ^ (Common.hexdump s) ^ "\""
    | V_Bigint s -> "0x" ^ (Common.hexdump s)

    | V_List [] -> "[]"
    | V_Dict d when (Hashtbl.length d = 0) -> "{}"

    | V_List l ->
      let list_aux dopts l = List.map (string_of_value dopts) l in
      constructed_aux "[" "]" list_aux l
    | V_Dict d ->
      let hash_aux dopts h =
	let fold_fun k v accu =
	  if dopts.raw_display || ((String.length k > 0) && (k.[0] != '_') && (k.[0] != '@'))
	  then (k ^ " -> " ^ (string_of_value dopts v))::accu
	  else accu
	in
	Hashtbl.fold fold_fun d []
      in
      constructed_aux "{" "}" hash_aux d

    | V_Object (n, obj_ref, d) ->
      let m = Hashtbl.find modules n in
      let module M = (val m : Module) in
      if not dopts.raw_display && (Hashtbl.mem M.param_getters "to_string") then begin
	match (Hashtbl.find M.param_getters "to_string") () with
	  | V_Function (NativeFun f) -> eval_as_string (f [v])
	  | _ -> raise NotImplemented
      end else begin
	M.enrich obj_ref d;
	string_of_value dopts (V_Dict d)
      end

    | (V_Unit | V_Function _ | V_Stream _ | V_OutChannel _
	  | V_Module _) as v -> "<" ^ (string_of_type v) ^ ">"
