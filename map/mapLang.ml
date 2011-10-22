(* Expression definition *)

type string_token =
   | ST_String of string
   | ST_Var of string
   | ST_Expr of string

let string_of_string_token = function
  | ST_String s -> String.escaped s
  | ST_Var s -> "$" ^ s
  | ST_Expr s -> "${" ^ s ^ "}"

type expression =
  | E_Bool of bool
  | E_Int of int
  | E_String of string_token list
  | E_Var of string

  | E_Concat of (expression * expression)
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

  | E_Exists of expression

  | E_Function of string list * expression list
  | E_Local of string list
  | E_Apply of expression * expression list
  | E_Return of expression

  | E_List of expression list
  | E_Cons of (expression * expression)
  | E_GetField of expression * string
  | E_SetField of expression * string * expression

  | E_Assign of (string * expression)
  | E_Unset of string
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

    | E_Concat (a, b) -> "(" ^ (soe a) ^ " ++ " ^ (soe b) ^ ")"
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

    | E_Exists e -> "exists " ^ (soe e)

    | E_Function (arg_names, body) ->
      "fun (" ^ (String.concat ", " arg_names) ^
	"{\n" ^ (soes body) ^ indent ^ "}"
    | E_Local id -> "local " ^ (String.concat ", " id)
    | E_Apply (e, args) ->
      (soe e) ^ " (" ^ (String.concat ", " (List.map soe args)) ^ ")"
    | E_Return e -> "return " ^ (soe e)

    | E_List e -> "[" ^ (String.concat ", " (List.map soe e)) ^ "]b"
    | E_Cons (e1, e2) -> (soe e1) ^ "::" ^ (soe e2)
    | E_GetField (e, f) -> (soe e) ^ "." ^ f
    | E_SetField (e, f, v) -> (soe e) ^ "." ^ f ^ " <- " ^ (soe v)

    | E_Assign (s, e) -> s ^ " := " ^ (soe e)
    | E_Unset s -> "unset " ^ s
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

