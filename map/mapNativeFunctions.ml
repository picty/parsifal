open MapLang


let print env args =
  let separator = getv_str env "_separator" "," in
  let endline = getv_str env "_endline" "\n" in
  print_string ((String.concat separator (List.map eval_as_string args)) ^ endline);
  V_Unit


let one_value_fun f = function
  | [e] -> f e
  | _ -> raise WrongNumberOfArguments

let one_string_fun f = function
  | [e] -> f (eval_as_string e)
  | _ -> raise WrongNumberOfArguments

let one_list_fun f = function
  | [e] -> f (eval_as_list e)
  | _ -> raise WrongNumberOfArguments

let two_value_fun f = function
  | [e1; e2] -> f e1 e2
  | _ -> raise WrongNumberOfArguments

let two_value_fun_with_env f env = function
  | [e1; e2] -> f env e1 e2
  | _ -> raise WrongNumberOfArguments

let two_string_fun f = function
  | [e1; e2] -> f (eval_as_string e1) (eval_as_string e2)
  | _ -> raise WrongNumberOfArguments


let length = function
  | V_String s -> V_Int (String.length s)
  | V_List l -> V_Int (List.length l)
  | _ -> raise (ContentError "String or list expected")


let parse_constrained_asn1 cons input =
  let pstate = match input with
    | V_String s ->
      Asn1.Engine.pstate_of_string
	(Asn1.Engine.default_error_handling_function
	   Asn1.Asn1EngineParams.S_SpecFatallyViolated
	   Asn1.Asn1EngineParams.S_OK) "(inline)" s
    | V_Stream (filename, s) ->
      Asn1.Engine.pstate_of_stream
	(Asn1.Engine.default_error_handling_function
	   Asn1.Asn1EngineParams.S_SpecFatallyViolated
	   Asn1.Asn1EngineParams.S_OK) filename s
    | _ -> raise (ContentError "String or stream expected")
  in
  Asn1Constraints.constrained_parse cons pstate

let parse_answer_dump input =
  let pstate = match input with
    | V_String s ->
      AnswerDump.pstate_of_string "(inline)" s
    | V_Stream (filename, s) ->
      AnswerDump.pstate_of_stream filename s
    | _ -> raise (ContentError "String or stream expected")
  in
  V_AnswerRecord (AnswerDump.parse_answer_record pstate)

let parse format input =
  match format with
    | V_String "x509" ->
      V_Certificate (parse_constrained_asn1 (X509.certificate_constraint X509.object_directory) input)
    | V_String "asn1" ->
      V_Asn1 (parse_constrained_asn1 (Asn1Constraints.Anything Common.identity) input)
    | V_String "answer" ->
      parse_answer_dump input
    | _ -> raise (ContentError ("Unknown format"))


let open_file filename = V_Stream (filename, Stream.of_channel (open_in filename))


let encode format input = match format with
  | "hex" -> V_String (Common.hexdump input)
  | _ -> raise (ContentError ("Unknown format"))


let filter env f l =
  match f, l with
    | V_Function (NativeFun f), V_List l ->
      V_List (List.filter (fun elt -> eval_as_bool (f [elt])) l)

    | V_Function (NativeFunWithEnv f), V_List l ->
      V_List (List.filter (fun elt -> eval_as_bool (f env [elt])) l)

    | V_Function (InterpretedFun ([arg1], body)), V_List l ->
      let filter_aux elt =
	let new_env = make_local_env env [arg1] [elt] in
	let retval = 
	  try
	    eval_exps new_env body
	  with
	    | ReturnValue v -> v
	in eval_as_bool retval
      in
      V_List (List.filter filter_aux l)

    | V_Function _, V_List _ -> raise (ContentError ("Wrong filter format"))
    | _ -> raise (ContentError ("(filter function, list) expected"))


let map env f l =
  match f, l with
    | V_Function (NativeFun f), V_List l ->
      V_List (List.map (fun elt -> f [elt]) l)

    | V_Function (NativeFunWithEnv f), V_List l ->
      V_List (List.map (fun elt -> f env [elt]) l)

    | V_Function (InterpretedFun ([arg1], body)), V_List l ->
      let filter_aux elt =
	let new_env = make_local_env env [arg1] [elt] in
	try
	  eval_exps new_env body
	with
	  | ReturnValue v -> v
      in
      V_List (List.map filter_aux l)

    | V_Function _, V_List _ -> raise (ContentError ("Wrong filter format"))
    | _ -> raise (ContentError ("(filter function, list) expected"))


let add_native name f =
  Hashtbl.replace global_env name (V_Function (NativeFun f))

let add_native_with_env name f =
  Hashtbl.replace global_env name (V_Function (NativeFunWithEnv f))

let _ =
  add_native_with_env "print" print;
  add_native "length" (one_value_fun length);
  add_native "parse" (two_value_fun parse);
  add_native "open" (one_string_fun open_file);
  add_native "encode" (two_string_fun encode);
  add_native "head" (one_list_fun List.hd);
  add_native "tail" (one_list_fun (fun l -> V_List (List.tl l)));
  add_native_with_env "filter" (two_value_fun_with_env filter);
  add_native_with_env "map" (two_value_fun_with_env map)
