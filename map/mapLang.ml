type string_token =
   | ST_String of string
   | ST_Var of string

let string_of_string_token = function
  | ST_String s -> String.escaped s
  | ST_Var s -> "$" ^ s

type expression =
  | E_Int of int
  | E_String of string_token list
  | E_Var of string

  | E_Plus of (expression * expression)
  | E_Minus of (expression * expression)
  | E_Mult of (expression * expression)
  | E_Div of (expression * expression)
  | E_Mod of (expression * expression)

  | E_Equal of (expression * expression)
  | E_Lt of (expression * expression)
  | E_In of (expression * expression)
  | E_Like of (expression * expression)

  | E_LAnd of (expression * expression)
  | E_LOr of (expression * expression)
  | E_LNot of expression

  | E_BAnd of (expression * expression)
  | E_BOr of (expression * expression)
  | E_BXor of (expression * expression)
  | E_BNot of expression

  | E_TypeOf of expression
  | E_Parse of expression
  | E_Open of expression

  | E_Function of command list
  | E_Apply of expression

and command =
  | C_Assign of (string * expression)
  | C_IfThenElse of (expression * command list * command list)
  | C_Print of expression
  | C_Return of expression


let rec string_of_expression indent = function
  | E_Int i -> string_of_int i
  | E_String sts ->
    "\"" ^ (String.concat "" (List.map string_of_string_token sts)) ^ "\""
  | E_Var s -> s

  | E_Plus (a, b) -> "(" ^ (string_of_expression indent a) ^ " + " ^ (string_of_expression indent b) ^ ")"
  | E_Minus (E_Int 0, b) -> "-" ^ (string_of_expression indent b)
  | E_Minus (a, b) -> "(" ^ (string_of_expression indent a) ^ " - " ^ (string_of_expression indent b) ^ ")"
  | E_Mult (a, b) -> "(" ^ (string_of_expression indent a) ^ " * " ^ (string_of_expression indent b) ^ ")"
  | E_Div (a, b) -> "(" ^ (string_of_expression indent a) ^ " / " ^ (string_of_expression indent b) ^ ")"
  | E_Mod (a, b) -> "(" ^ (string_of_expression indent a) ^ " % " ^ (string_of_expression indent b) ^ ")"

  | E_Equal (a, b) -> "(" ^ (string_of_expression indent a) ^ " == " ^ (string_of_expression indent b) ^ ")"
  | E_Lt (a, b) -> "(" ^ (string_of_expression indent a) ^ " < " ^ (string_of_expression indent b) ^ ")"
  | E_LNot (E_Lt (a, b)) -> "(" ^ (string_of_expression indent b) ^ " <= " ^ (string_of_expression indent a) ^ ")"
  | E_In (a, b) -> "(" ^ (string_of_expression indent a) ^ " in " ^ (string_of_expression indent b) ^ ")"
  | E_Like (a, b) -> "(" ^ (string_of_expression indent a) ^ " ~= " ^ (string_of_expression indent b) ^ ")"

  | E_LAnd (a, b) -> "(" ^ (string_of_expression indent a) ^ " && " ^ (string_of_expression indent b) ^ ")"
  | E_LOr (a, b) -> "(" ^ (string_of_expression indent a) ^ " || " ^ (string_of_expression indent b) ^ ")"
  | E_LNot a -> "! " ^ (string_of_expression indent a)

  | E_BAnd (a, b) -> "(" ^ (string_of_expression indent a) ^ " & " ^ (string_of_expression indent b) ^ ")"
  | E_BOr (a, b) -> "(" ^ (string_of_expression indent a) ^ " | " ^ (string_of_expression indent b) ^ ")"
  | E_BXor (a, b) -> "(" ^ (string_of_expression indent a) ^ " ^ " ^ (string_of_expression indent b) ^ ")"
  | E_BNot a -> "~ " ^ (string_of_expression indent a)

  | E_TypeOf e -> "typeof " ^ (string_of_expression indent e)
  | E_Parse e -> "parse " ^ (string_of_expression indent e)
  | E_Open e -> "open " ^ (string_of_expression indent e)

  | E_Function body ->
    let new_indent = indent ^ "  " in
    "fun {\n" ^ (string_of_commands new_indent body) ^ indent ^ "}"
  | E_Apply e -> (string_of_expression indent e) ^ " ()"

and string_of_command indent cmd =
  indent ^ (match cmd with
    | C_Assign (s, e) -> s ^ " := " ^ (string_of_expression indent e)
    | C_IfThenElse (i, t, []) ->
      let new_indent = indent ^ "  " in
      "if (" ^ (string_of_expression new_indent i) ^ ")\n" ^
	indent ^ "then\n" ^ (string_of_commands new_indent t) ^
	indent ^ "fi\n"
    | C_IfThenElse (i, t, e) ->
      let new_indent = indent ^ "  " in
      "if (" ^ (string_of_expression new_indent i) ^ ")\n" ^
	indent ^ "then\n" ^ (string_of_commands new_indent t) ^
	indent ^ "else\n" ^ (string_of_commands new_indent e) ^
	indent ^ "fi\n"
    | C_Print e -> "print (" ^ (string_of_expression indent e) ^ ")"
    | C_Return e -> "return " ^ (string_of_expression indent e)
  ) ^ "\n"

and string_of_commands indent cmds =
  String.concat "" (List.map (string_of_command indent) cmds)




type value =
  | V_Unit
  | V_Bool of bool
  | V_Int of int
  | V_String of string
  | V_Stream of string * char Stream.t
  | V_Certificate of X509.certificate
  | V_Function of command list

type set_variable = string -> value -> unit
type get_variable = string -> value

exception NotImplemented
exception ContentError of string
exception ReturnValue of value


let eval_as_string = function
  | V_Bool b -> string_of_bool b
  | V_Int i -> string_of_int i
  | V_String s -> s
  | V_Certificate c -> X509.string_of_certificate true "" (Some X509.name_directory) c
  | V_Unit
  | V_Function _
  | V_Stream _ -> raise (ContentError "String expected")

let eval_as_int = function
  | V_Int i -> i
  | V_String s -> int_of_string s
  | V_Unit
  | V_Bool _
  | V_Stream _
  | V_Function _
  | V_Certificate _ -> raise (ContentError "Integer expected")

let eval_as_bool = function
  | V_Bool b -> b
  | V_Int i -> i <> 0
  | V_String s -> (String.length s) <> 0
  | V_Unit
  | V_Stream _
  | V_Function _
  | V_Certificate _ -> raise (ContentError "Boolean expected")

let eval_as_function = function
  | V_Function body -> body
  | V_Unit | V_Bool _ | V_Int _ | V_String _ | V_Stream _ | V_Certificate _ -> raise (ContentError "Function expected")

let string_of_type = function
  | V_Unit -> "unit"
  | V_Bool _ -> "bool"
  | V_Int _ -> "int"
  | V_String _ -> "string"
  | V_Stream _ -> "stream"
  | V_Certificate _ -> "certificate"
  | V_Function _ -> "function"


let eval_string_token getv = function
  | ST_String s -> s
  | ST_Var s -> eval_as_string (getv s)

let rec eval_exp getv setv = function
  | E_Int i -> V_Int i
  | E_String l -> V_String (String.concat "" (List.map (eval_string_token getv) l))
  | E_Var s -> getv s

  | E_Plus (a, b) -> begin
    match eval_exp getv setv a, eval_exp getv setv b with
      | V_Int i1, V_Int i2 -> V_Int (i1 + i2)
      | v1, v2 -> V_String ((eval_as_string v1) ^ (eval_as_string v2))
  end
  | E_Minus (a, b) -> V_Int (eval_as_int (eval_exp getv setv a) - eval_as_int (eval_exp getv setv b))
  | E_Mult (a, b) -> V_Int (eval_as_int (eval_exp getv setv a) * eval_as_int (eval_exp getv setv b))
  | E_Div (a, b) -> V_Int (eval_as_int (eval_exp getv setv a) / eval_as_int (eval_exp getv setv b))
  | E_Mod (a, b) -> V_Int (eval_as_int (eval_exp getv setv a) mod eval_as_int (eval_exp getv setv b))

  | E_Equal (a, b) -> V_Bool (match eval_exp getv setv a, eval_exp getv setv b with
      | V_Bool b1, V_Bool b2 -> b1 = b2
      | V_Int i1, V_Int i2 -> i1 = i2
      | V_String s1, V_String s2 -> s1 = s2
      | v1, v2 -> eval_as_string v1 = eval_as_string v2
  )
    
  | E_Lt (a, b) -> V_Bool (eval_as_int (eval_exp getv setv a) < eval_as_int (eval_exp getv setv b))
  | E_In _
  | E_Like _ -> raise NotImplemented

  | E_LAnd (a, b) -> V_Bool (eval_as_bool (eval_exp getv setv a) && eval_as_bool (eval_exp getv setv b))
  | E_LOr (a, b) -> V_Bool (eval_as_bool (eval_exp getv setv a) || eval_as_bool (eval_exp getv setv b))
  | E_LNot e -> V_Bool (not (eval_as_bool (eval_exp getv setv e)))

  | E_BAnd (a, b) -> V_Int (eval_as_int (eval_exp getv setv a) land eval_as_int (eval_exp getv setv b))
  | E_BOr (a, b) -> V_Int (eval_as_int (eval_exp getv setv a) lor eval_as_int (eval_exp getv setv b))
  | E_BXor (a, b) -> V_Int (eval_as_int (eval_exp getv setv a) lxor eval_as_int (eval_exp getv setv b))
  | E_BNot e -> V_Int (lnot (eval_as_int (eval_exp getv setv e)))

  | E_TypeOf e -> V_String (string_of_type (eval_exp getv setv e))
  | E_Parse e ->
    let pstate = match eval_exp getv setv e with
      | V_String s ->
	Asn1.Engine.pstate_of_string
	  (Asn1.Engine.default_error_handling_function
	     Asn1.Asn1EngineParams.S_SpecFatallyViolated
	     Asn1.Asn1EngineParams.S_OK) "inline_parse" s
      | V_Stream (filename, s) ->
	Asn1.Engine.pstate_of_stream
	  (Asn1.Engine.default_error_handling_function
	     Asn1.Asn1EngineParams.S_SpecFatallyViolated
	     Asn1.Asn1EngineParams.S_OK) filename s
      | _ -> raise (ContentError "String or stream expected")
    in
    (* TODO: inline_parse, really ? *)
    V_Certificate (Asn1Constraints.constrained_parse (X509.certificate_constraint X509.object_directory) pstate)
  | E_Open e ->
    let filename = eval_as_string (eval_exp getv setv e) in
    V_Stream (filename, Stream.of_channel (open_in filename))
  | E_Function cmd -> V_Function cmd
  | E_Apply e -> begin
    try
      List.iter (eval_command getv setv) (eval_as_function (eval_exp getv setv e));
      V_Unit
    with
      | ReturnValue v -> v
  end

and eval_command getv setv = function
  | C_Assign (var, e) -> setv var (eval_exp getv setv e)
  | C_IfThenElse (i, t, e) ->
    List.iter (eval_command getv setv) 
      (if (eval_as_bool (eval_exp getv setv i)) then t else e)
  | C_Print e -> print_endline (eval_as_string (eval_exp getv setv e))
  | C_Return e -> raise (ReturnValue (eval_exp getv setv e))
