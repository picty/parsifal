open Types
open Modules


module PrinterLib = struct
  let name = "printer"

  let raw_display = ref false  (* Display objects as dictionnaries *)
  let multiline = ref false    (* Is it multiline? *)
  let indent = ref "  "        (* If we are multiline, here is the indent for each level *)    
  let separator = ref ", "     (* If not multiline, here is the separator *)
  let endline = ref "\n"
  let resolve_names = ref true

  let params = [
    param_from_bool_ref "raw_display" raw_display;
    param_from_bool_ref "multiline" multiline;
    param_from_string_ref "indent" indent;
    param_from_string_ref "separator" separator;
    param_from_string_ref "endline" endline;
    param_from_bool_ref "resolve_names" resolve_names
  ]



  let _string_of_strlist o f cur_indent str_content = 
    if !multiline then begin
      let new_indent = cur_indent ^ !indent in
      o ^ "\n" ^ new_indent ^ (String.concat ("\n" ^ new_indent) str_content) ^
	(if f <> "" then ("\n" ^ cur_indent ^ f) else "")
    end else
      o ^ (String.concat !separator str_content) ^ f

  let _string_of_constructed o f cur_indent mk_content content =
    let str_content = mk_content cur_indent true content in
    _string_of_strlist o f cur_indent str_content

  let rec _string_of_value cur_indent quote_strings v =
    match v with
      | V_Bool b -> string_of_bool b
      | V_Int i -> string_of_int i
      | V_String s -> if (quote_strings) then "\"" ^ (Common.quote_string s) ^ "\"" else s
      | V_BinaryString s -> if (quote_strings) then "\"" ^ (Common.hexdump s) ^ "\"" else Common.hexdump s
      | V_BitString (n, s) -> "\"[" ^ (string_of_int n) ^ "]" ^ (Common.hexdump s) ^ "\""
      | V_Bigint s -> "0x" ^ (Common.hexdump s)

      | V_List [] -> "[]"
      | V_Dict d when (Hashtbl.length d = 0) -> "{}"

      | V_List l ->
	let list_aux n_i q_s l = List.map (_string_of_value n_i q_s) l in
	_string_of_constructed "[" "]" cur_indent list_aux l
      | V_Dict d ->
	let hash_aux n_i q_s h =
	  let fold_fun k v accu =
	    if !raw_display || ((String.length k > 0) && (k.[0] != '_') && (k.[0] != '@'))
	    then (k ^ " -> " ^ (_string_of_value n_i q_s v))::accu
	    else accu
	  in
	  Hashtbl.fold fold_fun d []
	in
	_string_of_constructed "{" "}" cur_indent hash_aux d

      | V_Object (n, obj_ref, d) ->
	let m = Hashtbl.find modules n in
	let module M = (val m : Module) in
	if not !raw_display && (Hashtbl.mem M.static_params "to_string_indent") then begin
	  match (Hashtbl.find M.static_params "to_string_indent") with
	    | V_Function (NativeFun f) -> eval_as_string (f [V_String cur_indent; v])
	    | _ -> raise (ContentError "to_string_indent should be a native function")
	end else begin
	  M.enrich obj_ref d;
	  _string_of_value cur_indent true (V_Dict d)
	end

      | (V_Unit | V_Function _ | V_Stream _ | V_OutChannel _
	    | V_Module _) as v -> "<" ^ (string_of_type v) ^ ">"

  let string_of_value = _string_of_value "" false


  let functions = []
end

module PrinterModule = MakeLibraryModule (PrinterLib)
let _ = add_module ((module PrinterModule : Module))
