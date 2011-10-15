type variable =
  | VBool of bool
  | VInt of int
(*  | VBigInt of Big_int.big_int *)
  | VString of string

type environment = (string, variable) Hashtbl.t

type b_expression =
  | BLocalVar of string
  | BGlobalVar of string
  | BConst of bool

  | BAnd of b_expression * b_expression
  | BOr of b_expression * b_expression
  | BNot of b_expression
  | BXor of b_expression * b_expression

  | IEq of i_expression * i_expression
  | ILe of i_expression * i_expression
  | ILt of i_expression * i_expression

  | SEq of s_expression * s_expression
  | SContains of s_expression * s_expression
  | SBeginsWith of s_expression * s_expression
  | SEndsWith of s_expression * s_expression

and i_expression =
  | ILocalVar of string
  | IGlobalVar of string
  | IConst of int

  | INeg of i_expression
  | IPlus of i_expression * i_expression
  | IMinus of i_expression * i_expression
  | IMult of i_expression * i_expression
  | IDiv of i_expression * i_expression
  | IMod of i_expression * i_expression

  | IAnd of i_expression * i_expression
  | IOr of i_expression * i_expression
  | IXor of i_expression * i_expression
  | INot of i_expression

  | SLen of s_expression

and s_expression =
  | SLocalVar of string
  | SGlobalVar of string
  | SConst of string

  | SConcat of s_expression list


let extract_bool env n =
  match Hashtbl.find env n with
    | VBool b -> b
    | VInt i -> i <> 0
    | VString s -> String.length s <> 0

let extract_int env n =
  match Hashtbl.find env n with
    | VBool b -> if b then 1 else 0
    | VInt i -> i
    | VString s -> int_of_string s

let extract_string env n =
  match Hashtbl.find env n with
    | VBool b -> string_of_bool b
    | VInt i -> string_of_int i
    | VString s -> s


let rec eval_bexp genv lenv = function
  | BLocalVar s -> extract_bool lenv s
  | BGlobalVar s -> extract_bool genv s
  | BConst b -> b

  | BAnd (b1, b2) -> (eval_bexp genv lenv b1) && (eval_bexp genv lenv b2)
  | BOr  (b1, b2) -> (eval_bexp genv lenv b1) || (eval_bexp genv lenv b2)
  | BXor (b1, b2) -> (eval_bexp genv lenv b1) <> (eval_bexp genv lenv b2)
  | BNot b -> not (eval_bexp genv lenv b)

  | IEq (i1, i2) -> (eval_iexp genv lenv i1) = (eval_iexp genv lenv i2)
  | ILe (i1, i2) -> (eval_iexp genv lenv i1) <= (eval_iexp genv lenv i2)
  | ILt (i1, i2) -> (eval_iexp genv lenv i1) < (eval_iexp genv lenv i2)

  | SEq (s1, s2) -> (eval_sexp genv lenv s1) = (eval_sexp genv lenv s2)

  | SContains (s, pat)
  | SBeginsWith (s, pat)
  | SEndsWith (s, pat) -> failwith "NotImplemented"

and eval_iexp genv lenv = function
  | ILocalVar s -> extract_int lenv s
  | IGlobalVar s -> extract_int genv s
  | IConst i -> i

  | INeg i -> - (eval_iexp genv lenv i)
  | IPlus (i1, i2) -> (eval_iexp genv lenv i1) + (eval_iexp genv lenv i2)
  | IMinus (i1, i2) -> (eval_iexp genv lenv i1) - (eval_iexp genv lenv i2)
  | IMult (i1, i2) -> (eval_iexp genv lenv i1) * (eval_iexp genv lenv i2)
  | IDiv (i1, i2) -> (eval_iexp genv lenv i1) / (eval_iexp genv lenv i2)
  | IMod (i1, i2) -> (eval_iexp genv lenv i1) mod (eval_iexp genv lenv i2)

  | IAnd (i1, i2) -> (eval_iexp genv lenv i1) land (eval_iexp genv lenv i2)
  | IOr (i1, i2) -> (eval_iexp genv lenv i1) lor (eval_iexp genv lenv i2)
  | IXor (i1, i2) -> (eval_iexp genv lenv i1) lxor (eval_iexp genv lenv i2)
  | INot i -> lnot (eval_iexp genv lenv i)

  | SLen s -> String.length (eval_sexp genv lenv s)

and eval_sexp genv lenv = function
  | SLocalVar s -> extract_string lenv s
  | SGlobalVar s -> extract_string genv s
  | SConst s -> s

  | SConcat sl -> String.concat "" (List.map (eval_sexp genv lenv) sl)


