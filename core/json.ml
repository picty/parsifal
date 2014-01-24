open Parsifal

let rec json_of_value ?verbose:(verbose=false) ?indent:(indent="") = function
  | VUnit -> "null"
  | VBool b -> string_of_bool b
  | VSimpleInt i | VInt (i, _, _) -> string_of_int i
  | VBigInt (s, _) | VString (s, true) -> "\"" ^ (hexdump s) ^ "\""
  | VString (s, false) -> quote_string s
  | VEnum (s, _, _, _) -> quote_string s

  | VList l ->
    let new_indent = indent ^ "  " in
    let handle_elt v = json_of_value ~verbose:verbose ~indent:new_indent v in
    Printf.sprintf "[\n%s%s\n%s]" new_indent
      (String.concat (",\n" ^ new_indent) (List.map handle_elt l))
      indent

  | VRecord l -> begin
    try
      if verbose
      then raise Not_found
      else string_of_value (List.assoc "@string_of" l)
    with Not_found -> begin
      let new_indent = indent ^ "  " in
      let handle_field accu (name, raw_v) = match (name, realise_value raw_v) with
	| _, VUnit -> accu
	| _, VOption None -> accu
	| name, v ->
	  if verbose || (String.length name > 1 && name.[0] <> '@')
	  then
	    (Printf.sprintf "%s: %s" (quote_string name)
	       (json_of_value ~verbose:verbose ~indent:new_indent v))::accu
	  else accu
      in
      Printf.sprintf "{\n%s%s\n%s}" new_indent
	(String.concat (",\n" ^ new_indent) (List.rev (List.fold_left handle_field [] l)))
	indent
    end
  end

  | VOption None -> "null"
  | VOption (Some v) -> json_of_value v
  | VError _ -> failwith "json_of_value encountered an error in the value"
  | VLazy v -> json_of_value (Lazy.force v)
  | VUnparsed v -> json_of_value v
