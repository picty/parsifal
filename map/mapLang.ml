(* Expression definition *)

type string_token =
   | ST_String of string
   | ST_Var of string

let string_of_string_token = function
  | ST_String s -> String.escaped s
  | ST_Var s -> "$" ^ s

type expression =
  | E_Bool of bool
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

  | E_Function of string list * expression list
  | E_Local of string
  | E_Apply of expression * expression list
  | E_Return of expression

  | E_List of expression list

  | E_Assign of (string * expression)
  | E_IfThenElse of (expression * expression list * expression list)
  | E_While of (expression * expression list)
  | E_Continue
  | E_Break

let rec string_of_exp indent exp =
  let soe = string_of_exp indent in
  let new_indent = indent ^ "  " in
  let soes = string_of_exps new_indent in
  match exp with
    | E_Bool b -> string_of_bool b
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

    | E_Function (arg_names, body) ->
      "fun (" ^ (String.concat ", " arg_names) ^
	"{\n" ^ (soes body) ^ indent ^ "}"
    | E_Local id -> "local " ^ id
    | E_Apply (e, args) ->
      (soe e) ^ " (" ^ (String.concat ", " (List.map soe args)) ^ ")"
    | E_Return e -> "return " ^ (soe e)

    | E_List e -> "[" ^ (String.concat ", " (List.map soe e)) ^ "]b"

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

    | E_While (cond, body) ->
      "while (" ^ (soe cond) ^ ") do\n" ^
	(soes body) ^ indent ^ "done\n"
    | E_Continue -> "continue"
    | E_Break -> "break"

and string_of_exps indent cmds =
  let aux cmd = indent ^ (string_of_exp indent cmd) ^ "\n" in
  String.concat "" (List.map aux cmds)



(* Value and environment handling *)

type function_sort =
  | NativeFun of (environment -> expression list -> value)
  | InterpretedFun of (string list * expression list)

and value =
  | V_Unit
  | V_Bool of bool
  | V_Int of int
  | V_String of string
  | V_Function of function_sort
  | V_List of value list
  | V_Stream of string * char Stream.t
  | V_OutChannel of string * out_channel
  | V_Certificate of X509.certificate

and environment = (string, value) Hashtbl.t list

let global_env : (string, value) Hashtbl.t = Hashtbl.create 100

exception NotImplemented
exception WrongNumberOfArguments
exception ContentError of string
exception ReturnValue of value
exception Continue
exception Break


let rec eval_as_string = function
  | V_Bool b -> string_of_bool b
  | V_Int i -> string_of_int i
  | V_String s -> s
  | V_List l ->
    "[" ^ (String.concat ", " (List.map eval_as_string l)) ^ "]"
  | V_Certificate c -> X509.string_of_certificate true "" (Some X509.name_directory) c
  | V_Unit | V_Function _ | V_Stream _ | V_OutChannel _ ->
    raise (ContentError "String expected")

let eval_as_int = function
  | V_Int i -> i
  | V_String s -> int_of_string s
  | V_Unit | V_Bool _ | V_Function _ | V_List _ | V_Stream _
  | V_OutChannel _ | V_Certificate _ ->
    raise (ContentError "Integer expected")

let eval_as_bool = function
  | V_Bool b -> b
  | V_Int 0 -> false
  | V_Int _ -> true
  | V_String s -> (String.length s) <> 0
  | V_List [] -> false
  | V_List _ -> true
  | V_Stream (_, s) -> not (Common.eos s)
  | V_Unit | V_Function _ | V_OutChannel _ | V_Certificate _ ->
    raise (ContentError "Boolean expected")

let eval_as_function = function
  | V_Function body -> body
  | V_Unit | V_Bool _ | V_Int _ | V_String _ | V_List _
  | V_Stream _ | V_OutChannel _ | V_Certificate _ ->
    raise (ContentError "Function expected")

let eval_as_list = function
  | V_List l -> l
  | V_Unit | V_Bool _ | V_Int _ | V_String _ | V_Function _
  | V_Stream _ | V_OutChannel _ | V_Certificate _ ->
    raise (ContentError "List expected")

let string_of_type = function
  | V_Unit -> "unit"
  | V_Bool _ -> "bool"
  | V_Int _ -> "int"
  | V_String _ -> "string"
  | V_Function _ -> "function"
  | V_List _ -> "list"
  | V_Stream _ -> "stream"
  | V_OutChannel _ -> "outchannel"
  | V_Certificate _ -> "certificate"

let rec getv env name = match env with
  | [] -> raise Not_found
  | e::r -> begin
    try
      Hashtbl.find e name
    with
      | Not_found -> getv r name
  end

let rec setv env name v = match env with
  | [] -> raise Not_found
  | [e] -> Hashtbl.replace e name v
  | e::r ->
    if Hashtbl.mem e name
    then Hashtbl.replace e name v
    else setv r name v

let eval_string_token env = function
  | ST_String s -> s
  | ST_Var s -> eval_as_string (getv env s)

let make_local_env env args values =
  let na = List.length args in
  let nv = List.length values in
  if na <> nv
  then raise WrongNumberOfArguments
  else begin
    let local_env = Hashtbl.create (2 * na) in
    let rec instanciate = function
      | [], [] -> ()
      | a::rargs, v::rvalues ->
	Hashtbl.replace local_env a v;
	instanciate (rargs, rvalues)
      | _ -> raise WrongNumberOfArguments
    in
    instanciate (args, values);
    local_env::env
  end



(* Interpretation *)

let rec eval_exp env exp =
  let eval = eval_exp env in
  match exp with
    | E_Bool b -> V_Bool b
    | E_Int i -> V_Int i
    | E_String l -> V_String (String.concat "" (List.map (eval_string_token env) l))
    | E_Var s -> getv env s

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

    | E_Function (arg_names, e) -> V_Function (InterpretedFun (arg_names, e))
    | E_Local id -> begin
      match env with
	| [] -> raise Not_found
	| e::_ -> Hashtbl.replace e id V_Unit
      end;
      V_Unit
    | E_Apply (e, args) -> begin
      match eval_as_function (eval e) with
	| NativeFun f -> f env args
	| InterpretedFun (arg_names, body) ->
	  let arg_values = List.map eval args in
	  let new_env = make_local_env env arg_names arg_values in
	  try
	    eval_exps new_env body;
	  with
	    | ReturnValue v -> v
    end
    | E_Return e -> raise (ReturnValue (eval e))

    | E_List e -> V_List (List.map eval e)

    | E_Assign (var, e) ->
      setv env var (eval e);
      V_Unit
    | E_IfThenElse (i, t, e) ->
      eval_exps env (if (eval_as_bool (eval i)) then t else e)
    | E_While (cond, body) -> begin
      try
	while (eval_as_bool (eval cond)) do
	  try
	    ignore (eval_exps env body)
	  with Continue -> ()
	done;
	V_Unit;
      with Break -> V_Unit
    end
    | E_Continue -> raise Continue
    | E_Break -> raise Break

and eval_exps env = function
  | [] -> V_Unit
  | [e] -> eval_exp env e
  | e::r ->
    ignore (eval_exp env e);
    eval_exps env r
