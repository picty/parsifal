open MapLang


let print env args =
  let aux arg = print_endline (eval_as_string (eval_exp env arg)) in
  List.iter aux args;
  V_Unit


let one_value_fun f env = function
  | [e] -> f (eval_exp env e)
  | _ -> raise WrongNumberOfArguments

let one_string_fun f env = function
  | [e] -> f (eval_as_string (eval_exp env e))
  | _ -> raise WrongNumberOfArguments

let one_list_fun f env = function
  | [e] -> f (eval_as_list (eval_exp env e))
  | _ -> raise WrongNumberOfArguments

let two_string_fun f env = function
  | [e1; e2] ->
    f (eval_as_string (eval_exp env e1))
      (eval_as_string (eval_exp env e2))
  | _ -> raise WrongNumberOfArguments


let length = function
  | V_String s -> V_Int (String.length s)
  | V_List l -> V_Int (List.length l)
  | _ -> raise (ContentError "String or list expected")

let parse_x509 v =
  let pstate = match v with
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
  V_Certificate (Asn1Constraints.constrained_parse (X509.certificate_constraint X509.object_directory) pstate)

let open_file filename = V_Stream (filename, Stream.of_channel (open_in filename))


let encode format input = match format with
  | "hex" -> V_String (Common.hexdump input)
  | _ -> raise (ContentError ("Unknown format"))


let add_native name f =
  Hashtbl.replace global_env name (V_Function (NativeFun f))

let _ =
  add_native "print" print;
  add_native "length" (one_value_fun length);
  add_native "parse" (one_value_fun parse_x509);
  add_native "open" (one_string_fun open_file);
  add_native "head" (one_list_fun List.hd);
  add_native "tail" (one_list_fun (fun l -> V_List (List.tl l)));
  add_native "encode" (two_string_fun encode)
