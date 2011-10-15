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

  | E_Function of expression list
  | E_Apply of expression

  | E_Assign of (string * expression)
  | E_IfThenElse of (expression * expression list * expression list)
  | E_Print of expression
  | E_Return of expression


let rec string_of_exp indent exp =
  let soe = string_of_exp indent in
  let new_indent = indent ^ "  " in
  let soes = string_of_exps new_indent in
  match exp with
    | E_Int i -> string_of_int i
    | E_String sts ->
      "\"" ^ (String.concat "" (List.map string_of_string_token sts)) ^ "\""
    | E_Var s -> s

    | E_Plus (a, b) -> "(" ^ (soe a) ^ " + " ^ (soe b) ^ ")"
    | E_Minus (E_Int 0, b) -> "-" ^ (soe b)
    | E_Minus (a, b) -> "(" ^ (soe a) ^ " - " ^ (soe b) ^ ")"
    | E_Mult (a, b) -> "(" ^ (soe a) ^ " * " ^ (soe b) ^ ")"
    | E_Div (a, b) -> "(" ^ (soe a) ^ " / " ^ (soe b) ^ ")"
    | E_Mod (a, b) -> "(" ^ (soe a) ^ " % " ^ (soe b) ^ ")"

    | E_Equal (a, b) -> "(" ^ (soe a) ^ " == " ^ (soe b) ^ ")"
    | E_Lt (a, b) -> "(" ^ (soe a) ^ " < " ^ (soe b) ^ ")"
    | E_LNot (E_Lt (a, b)) -> "(" ^ (soe b) ^ " <= " ^ (soe a) ^ ")"
    | E_In (a, b) -> "(" ^ (soe a) ^ " in " ^ (soe b) ^ ")"
    | E_Like (a, b) -> "(" ^ (soe a) ^ " ~= " ^ (soe b) ^ ")"

    | E_LAnd (a, b) -> "(" ^ (soe a) ^ " && " ^ (soe b) ^ ")"
    | E_LOr (a, b) -> "(" ^ (soe a) ^ " || " ^ (soe b) ^ ")"
    | E_LNot a -> "! " ^ (soe a)

    | E_BAnd (a, b) -> "(" ^ (soe a) ^ " & " ^ (soe b) ^ ")"
    | E_BOr (a, b) -> "(" ^ (soe a) ^ " | " ^ (soe b) ^ ")"
    | E_BXor (a, b) -> "(" ^ (soe a) ^ " ^ " ^ (soe b) ^ ")"
    | E_BNot a -> "~ " ^ (soe a)

    | E_TypeOf e -> "typeof " ^ (soe e)
    | E_Parse e -> "parse " ^ (soe e)
    | E_Open e -> "open " ^ (soe e)

    | E_Function body -> "fun {\n" ^ (soes body) ^ indent ^ "}"
    | E_Apply e -> (soe e) ^ " ()"

    | E_Assign (s, e) -> s ^ " := " ^ (soe e)
    | E_IfThenElse (i, t, []) ->
      "if (" ^ (soe i) ^ ")\n" ^
	indent ^ "then\n" ^ (soes t) ^
	indent ^ "fi\n"
    | E_IfThenElse (i, t, e) ->
      "if (" ^ (soe i) ^ ")\n" ^
	indent ^ "then\n" ^ (soes t) ^
	indent ^ "else\n" ^ (soes e) ^
	indent ^ "fi\n"
    | E_Print e -> "print (" ^ (soe e) ^ ")"
    | E_Return e -> "return " ^ (soe e)

and string_of_exps indent cmds =
  let aux cmd = indent ^ (string_of_exp indent cmd) ^ "\n" in
  String.concat "" (List.map aux cmds)



type value =
  | V_Unit
  | V_Bool of bool
  | V_Int of int
  | V_String of string
  | V_Stream of string * char Stream.t
  | V_Certificate of X509.certificate
  | V_Function of expression list

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

let rec eval_exp getv setv exp =
  let eval = eval_exp getv setv in
  match exp with
    | E_Int i -> V_Int i
    | E_String l -> V_String (String.concat "" (List.map (eval_string_token getv) l))
    | E_Var s -> getv s

    | E_Plus (a, b) -> begin
      match eval a, eval b with
	| V_Int i1, V_Int i2 -> V_Int (i1 + i2)
	| v1, v2 -> V_String ((eval_as_string v1) ^ (eval_as_string v2))
    end
    | E_Minus (a, b) -> V_Int (eval_as_int (eval a) - eval_as_int (eval b))
    | E_Mult (a, b) -> V_Int (eval_as_int (eval a) * eval_as_int (eval b))
    | E_Div (a, b) -> V_Int (eval_as_int (eval a) / eval_as_int (eval b))
    | E_Mod (a, b) -> V_Int (eval_as_int (eval a) mod eval_as_int (eval b))

    | E_Equal (a, b) -> V_Bool (match eval a, eval b with
	| V_Bool b1, V_Bool b2 -> b1 = b2
	| V_Int i1, V_Int i2 -> i1 = i2
	| V_String s1, V_String s2 -> s1 = s2
	| v1, v2 -> eval_as_string v1 = eval_as_string v2
    )
    
    | E_Lt (a, b) -> V_Bool (eval_as_int (eval a) < eval_as_int (eval b))
    | E_In _
    | E_Like _ -> raise NotImplemented

    | E_LAnd (a, b) -> V_Bool (eval_as_bool (eval a) && eval_as_bool (eval b))
    | E_LOr (a, b) -> V_Bool (eval_as_bool (eval a) || eval_as_bool (eval b))
    | E_LNot e -> V_Bool (not (eval_as_bool (eval e)))

    | E_BAnd (a, b) -> V_Int (eval_as_int (eval a) land eval_as_int (eval b))
    | E_BOr (a, b) -> V_Int (eval_as_int (eval a) lor eval_as_int (eval b))
    | E_BXor (a, b) -> V_Int (eval_as_int (eval a) lxor eval_as_int (eval b))
    | E_BNot e -> V_Int (lnot (eval_as_int (eval e)))

    | E_TypeOf e -> V_String (string_of_type (eval e))
    | E_Parse e ->
      let pstate = match eval e with
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
      let filename = eval_as_string (eval e) in
      V_Stream (filename, Stream.of_channel (open_in filename))
    | E_Function e -> V_Function e
    | E_Apply e -> begin
      try
	eval_exps getv setv (eval_as_function (eval e));
      with
	| ReturnValue v -> v
    end

    | E_Assign (var, e) ->
      setv var (eval e);
      V_Unit
    | E_IfThenElse (i, t, e) ->
      eval_exps getv setv (if (eval_as_bool (eval i)) then t else e)
    | E_Print e ->
      print_endline (eval_as_string (eval e));
      V_Unit
    | E_Return e -> raise (ReturnValue (eval e))

and eval_exps getv setv = function
  | [] -> V_Unit
  | [e] -> eval_exp getv setv e
  | e::r ->
    ignore (eval_exp getv setv e);
    eval_exps getv setv r
  
