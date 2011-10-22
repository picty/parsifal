open MapLang
open MapEval


let one_value_fun f = function
  | [e] -> f e
  | _ -> raise WrongNumberOfArguments

let one_value_fun_with_env f env = function
  | [e] -> f env e
  | _ -> raise WrongNumberOfArguments

let one_string_fun_with_env f env = function
  | [e] -> f env (eval_as_string e)
  | _ -> raise WrongNumberOfArguments

let two_value_fun f = function
  | [e1; e2] -> f e1 e2
  | _ -> raise WrongNumberOfArguments

let two_value_fun_with_env f env = function
  | [e1; e2] -> f env e1 e2
  | _ -> raise WrongNumberOfArguments

let three_value_fun f = function
  | [e1; e2; e3] -> f e1 e2 e3
  | _ -> raise WrongNumberOfArguments



(* Generic functions *)

let typeof v = V_String (string_of_type v)

let print env args =
  let separator = getv_str env "_separator" "," in
  let endline = getv_str env "_endline" "\n" in
  print_string ((String.concat separator (List.map eval_as_string_rec args)) ^ endline);
  V_Unit

let length = function
  | V_String s -> V_Int (String.length s)
  | V_List l -> V_Int (List.length l)
  | _ -> raise (ContentError "String or list expected")



(* List and set functions *)

let head l = match (eval_as_list l) with
  | [] -> raise Not_found
  | h::_ -> h

let tail l = match (eval_as_list l) with
  | [] -> raise Not_found
  | _::r -> V_List r

let nth n l =
  let rec nth_aux n = function
  | [] -> raise Not_found
  | h::r -> if n = 0 then h else nth_aux (n-1) r
  in nth_aux (eval_as_int n) (eval_as_list l)


let rec import_list arg =
  let rec import_aux_stream accu s =
    if Common.eos s
    then V_List (List.rev accu)
    else import_aux_stream ((V_String (Common.pop_line s))::accu) s
  in
  match arg with
    | V_List l -> V_List l
    | V_Set s -> V_List (List.map (fun x -> V_String x) (StringSet.elements s))
    | V_Stream (_, s) -> import_aux_stream [] s
    | v -> V_List ([v])


let rec import_set args =
  let rec import_aux_list accu = function
    | [] -> accu
    | elt::r -> import_aux_list (StringSet.add (eval_as_string elt) accu) r
  in
  let rec import_aux_stream accu s =
    if Common.eos s
    then accu
    else import_aux_stream (StringSet.add (Common.pop_line s) accu) s
  in
  let rec aux accu = function
    | [] -> accu
    | (V_List l)::r -> aux (import_aux_list accu l) r
    | (V_Stream (_, s))::r -> aux (import_aux_stream accu s) r
    | (V_Set s):: r -> aux (StringSet.union accu s) r
    | v::r -> aux (StringSet.add (eval_as_string v) accu) r
  in
  V_Set (aux StringSet.empty args)



(* Dict functions *)

let hash_make = function
  | [] -> V_ValueDict (Hashtbl.create (20))
  | [n] -> V_ValueDict (Hashtbl.create (eval_as_int (n)))
  | _ -> raise WrongNumberOfArguments

let hash_get h f = match h with
  | V_Dict d -> Hashtbl.find d (eval_as_string f)
  | V_ValueDict d -> Hashtbl.find d f
  | _ -> raise (ContentError "Dictionary expected")

let hash_get_def h f v = try hash_get h f with Not_found -> v

let hash_get_all h f = match h with
  | V_Dict d -> V_List (Hashtbl.find_all d (eval_as_string f))
  | V_ValueDict d -> V_List (Hashtbl.find_all d f)
  | _ -> raise (ContentError "Dictionary expected")

let hash_set h f v =
  begin
    match h with
      | V_Dict d -> Hashtbl.replace d (eval_as_string f) v
      | V_ValueDict d -> Hashtbl.replace d f v
      | _ -> raise (ContentError "Dictionary expected")
  end;
  V_Unit

let hash_add h f v =
  begin
    match h with
      | V_Dict d -> Hashtbl.add d (eval_as_string f) v
      | V_ValueDict d -> Hashtbl.add d f v
      | _ -> raise (ContentError "Dictionary expected")
  end;
  V_Unit

let hash_unset h f =
  begin
    match h with
      | V_Dict d -> Hashtbl.remove d (eval_as_string f)
      | V_ValueDict d -> Hashtbl.remove d f
      | _ -> raise (ContentError "Dictionary expected")
  end;
  V_Unit



(* Iterable functions *)

let filter env f arg =
  let real_f = eval_as_function f in
  let filter_aux elt = eval_as_bool (eval_function env real_f [elt]) in
  let filter_aux_set elt = filter_aux (V_String elt) in
  match arg with
    | V_List l -> V_List (List.filter filter_aux l)
    | V_Set s -> V_Set (StringSet.filter filter_aux_set s)
    | _ -> raise (ContentError "Iterable value expected")

let map env f l =
  let real_f = eval_as_function f in
  let real_l = eval_as_list l in
  V_List (List.map (fun elt -> eval_function env real_f [elt]) real_l)

let iter env f arg =
  let real_f = eval_as_function f in
  let iter_aux elt = ignore (eval_function env real_f [elt]) in
  let iter_aux_set elt = iter_aux (V_String elt) in
  let iter_aux_dict preprocess k v = ignore (eval_function env real_f [preprocess k; v]) in
  begin
    match arg with
      | V_List l -> List.iter iter_aux l
      | V_Set s -> StringSet.iter iter_aux_set s
      | V_Dict d -> Hashtbl.iter (iter_aux_dict (fun x -> V_String x)) d
      | V_ValueDict d -> Hashtbl.iter (iter_aux_dict Common.identity) d
      | _ -> raise (ContentError "Iterable value expected")
  end;
  V_Unit


(* File and string functions *)

let open_file filename_v =
  let filename = eval_as_string filename_v in
  let f = open_in filename in
  Gc.finalise close_in_noerr f;
  V_Stream (filename, Stream.of_channel f)


let encode format input = match (eval_as_string format) with
  | "hex" -> V_String (Common.hexdump (eval_as_string input))
  | _ -> raise (ContentError ("Unknown format"))

let decode format input = match (eval_as_string format) with
  | "hex" -> V_String (Common.hexparse (eval_as_string input))
  | _ -> raise (ContentError ("Unknown format"))


let asn1_ehf = Asn1.Engine.default_error_handling_function
  Asn1.Asn1EngineParams.s_specfatallyviolated
  Asn1.Asn1EngineParams.s_ok

let parse_constrained_asn1 cons input =
  let pstate = match input with
    | V_String s ->
      Asn1.Engine.pstate_of_string asn1_ehf "(inline)" s
    | V_Stream (filename, s) ->
      Asn1.Engine.pstate_of_stream asn1_ehf filename s
    | _ -> raise (ContentError "String or stream expected")
  in
  Asn1Constraints.constrained_parse cons pstate

let parse_tls_record input =
  let pstate = match input with
    | V_String s ->
      Tls.pstate_of_string "(inline)" s
    | V_Stream (filename, s) ->
      Tls.pstate_of_stream filename s
    | _ -> raise (ContentError "String or stream expected")
  in
  V_TlsRecord (Tls.parse_record asn1_ehf pstate)

let parse env format input =
  try
    match format with
      | V_String "x509" ->
	V_Certificate (parse_constrained_asn1 (X509.certificate_constraint X509.object_directory) input)
      | V_String "dn" ->
	V_DN (parse_constrained_asn1 (X509.dn_constraint X509.object_directory "dn") input)
      | V_String "asn1" ->
	V_Asn1 (parse_constrained_asn1 (Asn1Constraints.Anything Common.identity) input)
      | V_String "tls" ->
	parse_tls_record input
      | V_String object_name ->
	begin
	  try 
	    let d = getv env object_name in
	    let real_f = eval_as_function (hash_get d (V_String "parse")) in
	    eval_function env real_f [input]
	  with
	    | Not_found -> raise (ContentError ("Unknown format"))
	end
      | _ -> raise (ContentError ("Unknown format"))
  with
    | Asn1.Engine.ParsingError (err, sev, pstate) ->
      output_string stderr ("Asn1 parsing error: " ^ (Asn1.Engine.string_of_exception err sev pstate) ^ "\n");
      flush stderr;
      V_Unit
    | Tls.Engine.ParsingError (err, sev, pstate) ->
      output_string stderr ("Tls parsing error: " ^ (Tls.Engine.string_of_exception err sev pstate) ^ "\n");
      flush stderr;
      V_Unit;;

let stream_of_string n s =
  V_Stream (eval_as_string n, Stream.of_string (eval_as_string s))

let concat_strings sep l =
  V_String (String.concat (eval_as_string sep)
	      (List.map (fun x -> eval_as_string x) (eval_as_list l)))



let add_native name f =
  Hashtbl.replace global_env name (V_Function (NativeFun f))

let add_native_with_env name f =
  Hashtbl.replace global_env name (V_Function (NativeFunWithEnv f))

let _ =
  (* Generic functions *)
  add_native "typeof" (one_value_fun typeof);
  add_native_with_env "print" print;
  add_native "length" (one_value_fun length);
  add_native_with_env "eval" (one_string_fun_with_env interpret_string);

  (* List and set functions *)
  add_native "head" (one_value_fun head);
  add_native "tail" (one_value_fun tail);
  add_native "nth" (two_value_fun nth);
  add_native "list" (one_value_fun import_list);
  add_native "set" import_set;

  (* Dict functions *)
  add_native "dict" hash_make;
  add_native "dget" (two_value_fun hash_get);
  add_native "dget_def" (three_value_fun hash_get_def);
  add_native "dget_all" (two_value_fun hash_get_all);
  add_native "dadd" (three_value_fun hash_add);
  add_native "dset" (three_value_fun hash_set);
  add_native "dunset" (two_value_fun hash_unset);

  (* Iterable functions *)
  add_native_with_env "filter" (two_value_fun_with_env filter);
  add_native_with_env "map" (two_value_fun_with_env map);
  add_native_with_env "iter" (two_value_fun_with_env iter);

  (* File and string functions *)
  add_native "open" (one_value_fun open_file);
  add_native "encode" (two_value_fun encode);
  add_native "decode" (two_value_fun decode);
  add_native_with_env "parse" (two_value_fun_with_env parse);
  add_native "stream" (two_value_fun stream_of_string);
  add_native "concat" (two_value_fun concat_strings);

  (* OS interface *)
  add_native "getenv" (one_value_fun (fun x -> V_String (Unix.getenv (eval_as_string x))))
