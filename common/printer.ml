open Common
open Types
open Modules

type print_options = {
  opening : string;
  closing : string;
  separator : string;
  multiline : bool;
}

let only_ml ml = { opening = ""; closing = ""; separator = ""; multiline = ml }
let indent_only = only_ml true
let list_options sep ml = { opening = "["; closing = "]"; separator = sep; multiline = ml }
let hash_options sep ml = { opening = "{"; closing = "}"; separator = sep; multiline = ml }


module PrinterLib = struct
  let name = "printer"

  let raw_display = ref false   (* Display objects as dictionnaries *)
  let indent = ref "  "         (* If we are multiline, here is the indent for each level *)    
  let multiline_dict = ref true (* Force multiline dictionnaries *)
  let separator = ref ", "      (* If not multiline, here is the separator *)
  let endline = ref "\n"
  let resolve_names = ref true

  let params = [
    param_from_bool_ref "raw_display" raw_display;
    param_from_string_ref "indent" indent;
    param_from_string_ref "separator" separator;
    param_from_string_ref "endline" endline;
    param_from_bool_ref "resolve_names" resolve_names
  ]


  let _single_line title s = match title with
    | None -> s
    | Some title_string ->
      if s = ""
      then title_string
      else title_string ^ ": " ^ s

  let _string_of_strlist title opts str_content =
    if opts.multiline
    then begin
      let partial = (_single_line title opts.opening)::
	(List.map (function s -> (!indent ^ s)) str_content) in
      (if opts.closing = "" then partial else partial@[opts.closing])
    end else [_single_line title (opts.opening ^ (String.concat opts.separator str_content) ^ opts.closing)]

  let rec _flatten_strlist str_accu multiline_accu (x : (string list) list) = match x with
    | [] -> List.rev str_accu, multiline_accu
    | ([])::r -> _flatten_strlist str_accu multiline_accu r
    | ([s])::r -> _flatten_strlist (s::str_accu) multiline_accu r
    | (s_list)::r ->
      let rec local_aux accu = function
	| [] -> accu
	| s::r -> local_aux (s::accu) r
      in
      _flatten_strlist (local_aux str_accu s_list) true r

  let flatten_strlist = _flatten_strlist [] false

  let rec _string_of_value title quote_strings v =
    match v with
      | V_Bool b -> [_single_line title (string_of_bool b)]
      | V_Int i -> [_single_line title (string_of_int i)]
      | V_String s ->
	let res = if (quote_strings) then "\"" ^ (quote_string s) ^ "\"" else s
	in [_single_line title (res)]
      | V_BinaryString s ->
	let res = if (quote_strings) then "[HEX]" ^ (hexdump s) else hexdump s
	in [_single_line title (res)]
      | V_BitString (n, s) ->
	[_single_line title ("\"[" ^ (string_of_int n) ^ "]" ^ (hexdump s) ^ "\"")]
      | V_Bigint s -> [_single_line title ("0x" ^ (hexdump s))]
      | V_IPv4 s -> [_single_line title (string_of_ip4 s)]

      | V_List l ->
	let content, multiline = flatten_strlist (List.map (_string_of_value None true) l) in
	_string_of_strlist title (list_options !separator multiline) content
	  
      | V_Dict d ->
	let hash_aux k v accu =
	  if !raw_display || ((String.length k > 0) && (k.[0] != '_') && (k.[0] != '@'))
	  then (_string_of_value (Some k) true v)::accu
	  else accu
	in
	let content, multiline = flatten_strlist (Hashtbl.fold hash_aux d []) in
	_string_of_strlist title (hash_options !separator (multiline || (!multiline_dict && content <> []))) content

      | V_Object (n, obj_ref, d) ->
	let module M = (val (hash_find modules n) : Module) in
	if not !raw_display && (Hashtbl.mem M.static_params "to_string_indent") then begin
	  let content = match (Hashtbl.find M.static_params "to_string_indent") with
	    | V_Function (NativeFun f) -> List.map eval_as_string (eval_as_list (f [v]))
	    | _ -> raise (ContentError "to_string_indent should be a native function")
	  in content
	  end else begin
	    M.enrich obj_ref d;
	    _string_of_value title true (V_Dict d)
	  end

      | (V_Unit | V_Function _ | V_Stream _ | V_OutChannel _
	    | V_Module _) as v -> [_single_line title ("<" ^ (string_of_type v) ^ ">")]

  let string_of_value v = String.concat "\n" (_string_of_value None false v)


  let functions = []
end

module PrinterModule = MakeLibraryModule (PrinterLib)
let _ = add_module ((module PrinterModule : Module))
