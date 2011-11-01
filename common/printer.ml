open Types
open Modules


module PrinterLib = struct
  let name = "printer"

  let raw_display = ref false  (* Display objects as dictionnaries *)
  let multiline = ref false    (* Is it multiline? *)
  let indent = ref "  "        (* If we are multiline, here is the indent for each level *)    
  let separator = ref ", "     (* If not multiline, here is the separator *)
  let endline = ref "\n"

  let params = [
    param_from_bool_ref "raw_display" raw_display;
    param_from_bool_ref "multiline" multiline;
    param_from_string_ref "indent" indent;
    param_from_string_ref "separator" separator;
    param_from_string_ref "endline" endline;
  ]

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


  let rec string_of_value_aux cur_indent quote_strings v =
    let constructed_aux o f mk_content content =
      if !multiline then begin
	let new_indent = cur_indent ^ !indent in
	let content = mk_content new_indent true content in
	o ^ "\n" ^ new_indent ^ (String.concat ("\n" ^ new_indent) content) ^ "\n" ^ cur_indent ^ f
      end else begin
	let content = mk_content cur_indent true content in
	o ^ (String.concat !separator content) ^ f
      end
    in
    match v with
      | V_Bool b -> string_of_bool b
      | V_Int i -> string_of_int i
      | V_String s -> if (quote_strings) then "\"" ^ (Common.quote_string s) ^ "\"" else s
      | V_BinaryString s -> "\"" ^ (Common.hexdump s) ^ "\""
      | V_BitString (n, s) -> "\"[" ^ (string_of_int n) ^ "]" ^ (Common.hexdump s) ^ "\""
      | V_Bigint s -> "0x" ^ (Common.hexdump s)

      | V_List [] -> "[]"
      | V_Dict d when (Hashtbl.length d = 0) -> "{}"

      | V_List l ->
	let list_aux n_i q_s l = List.map (string_of_value_aux n_i q_s) l in
	constructed_aux "[" "]" list_aux l
      | V_Dict d ->
	let hash_aux n_i q_s h =
	  let fold_fun k v accu =
	    if !raw_display || ((String.length k > 0) && (k.[0] != '_') && (k.[0] != '@'))
	    then (k ^ " -> " ^ (string_of_value_aux n_i q_s v))::accu
	    else accu
	  in
	  Hashtbl.fold fold_fun d []
	in
	constructed_aux "{" "}" hash_aux d

      | V_Object (n, obj_ref, d) ->
	let m = Hashtbl.find modules n in
	let module M = (val m : Module) in
	if not !raw_display && (Hashtbl.mem M.param_getters "to_string") then begin
	  match (Hashtbl.find M.param_getters "to_string") () with
	    | V_Function (NativeFun f) -> eval_as_string (f [v])
	    | _ -> raise NotImplemented
	end else begin
	  M.enrich obj_ref d;
	  string_of_value_aux cur_indent true (V_Dict d)
	end

      | (V_Unit | V_Function _ | V_Stream _ | V_OutChannel _
	    | V_Module _) as v -> "<" ^ (string_of_type v) ^ ">"

  let string_of_value = string_of_value_aux "" false


  let functions = []
end

module PrinterModule = MakeLibraryModule (PrinterLib)
let _ = add_module ((module PrinterModule : Module))
