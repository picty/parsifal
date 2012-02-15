(*********)
(* Types *)
(*********)

open Common
open Language


(* Value, function and environment types *)

(* TODO: Use a private type, to avoid unwanted constructions *)
type object_ref = ObjectRef of int;;

type function_sort =
  | NativeFun of (value list -> value)
  | NativeFunWithEnv of (environment -> value list -> value)
  | InterpretedFun of (environment * string list * expression list)

and getter = unit -> value
and setter = value -> unit

and value =
  | V_Unit
  | V_Bool of bool
  | V_Int of int
  | V_Enumerated of int * (int -> string)
  | V_String of string
  | V_BinaryString of string
  | V_BitString of int * string
  | V_Bigint of string
  | V_IPv4 of string
  | V_Function of function_sort

  | V_List of value list
  | V_Dict of (string, value) Hashtbl.t
  (* TODO: Separate V_Stream from V_FileDesc? *)
  | V_Stream of string * char Stream.t * Unix.file_descr option
  | V_OutChannel of string * out_channel

  | V_Module of string
  | V_Object of string * object_ref * (string, value) Hashtbl.t

and environment = (string, value) Hashtbl.t list

let global_env : (string, value) Hashtbl.t = Hashtbl.create 100



(* Exceptions *)
exception NotImplemented of string
exception ListTooShort
exception WrongNumberOfArguments
exception ContentError of string



(* Module handling *)

module type Module = sig
  val name : string
  val param_getters : (string, getter) Hashtbl.t
  val param_setters : (string, setter) Hashtbl.t
  val static_params : (string, value) Hashtbl.t

  val init : unit -> unit
end

module type ObjectModule = sig
  include Module

  type t
  val register : t -> value
  val pop_object : value -> t
  val enrich : object_ref -> (string, value) Hashtbl.t -> unit
  val update : object_ref -> (string, value) Hashtbl.t -> unit
end

let object_modules : (string, (module ObjectModule)) Hashtbl.t = Hashtbl.create 10
let library_modules : (string, (module Module)) Hashtbl.t = Hashtbl.create 10

let add_object_module m =
  let module M = (val m : ObjectModule) in
  M.init ();
  Hashtbl.replace object_modules M.name m;
  Hashtbl.replace global_env M.name (V_Module M.name)

let add_library_module m =
  let module M = (val m : Module) in
  M.init ();
  Hashtbl.replace library_modules M.name m;
  Hashtbl.replace global_env M.name (V_Module M.name)

let find_module n =
  try Hashtbl.find library_modules n
  with Not_found ->
    let m = hash_find object_modules n in
    let module M = (val m : ObjectModule) in
    (module M : Module)


(* Type lifters *)
let lift_int f arg = V_Int (f arg)
let lift_bool f arg = V_Bool (f arg)
let lift_string f arg = V_String (f arg)
let lift_bin_string f arg = V_BinaryString (f arg)
let lift_list f arg = V_List (f arg)
let lift_ipv4 f arg = V_IPv4 (f arg)


(* Type extractors *)

let eval_as_int = function
  | V_Int i
  | V_Enumerated (i, _) -> i
  | V_String s
  | V_BinaryString s -> int_of_string s
  | V_Bigint _ -> raise (NotImplemented "eval_as_int (V_Bigint)")
  | _ -> raise (ContentError "Integer expected")

let eval_as_bool = function
  | V_Bool b -> b
  | V_Unit | V_Int 0 | V_Enumerated (0, _) | V_List [] -> false
  | V_Int _ | V_Enumerated _ | V_List _ -> true
  | V_String s
  | V_BinaryString s
  | V_BitString (_, s) -> (String.length s) <> 0
  | V_Bigint s -> (String.length s) > 0 && s.[0] != '\x00'
  | V_Stream (_, s, _) -> not (eos s)
  | V_Dict d -> (Hashtbl.length d) <> 0
  | V_Object _ -> true

  | _ -> raise (ContentError "Boolean expected")

let eval_as_ipv4 = function
  | V_IPv4 s -> s
  | _ -> raise (ContentError "IPv4 expected")

let eval_as_function = function
  | V_Function f -> f
  | _ -> raise (ContentError "Function expected")

let eval_as_stream = function
  | V_Stream (n, s, descr) -> n, s, descr
  | _ -> raise (ContentError "Stream expected")

let eval_as_outchannel = function
  | V_OutChannel (n, s) -> n, s
  | _ -> raise (ContentError "Output channel expected")

let eval_as_dict = function
  | V_Dict d -> d
  | _ -> raise (ContentError "Dictionary expected")

let eval_as_object = function
  | V_Object (n, r, d) -> (n, r, d)
  | _ -> raise (ContentError "Object expected")

let eval_as_list = function
  | V_List l -> l
  | _ -> raise (ContentError "List expected")

let eval_as_string = function
  | V_Bool b -> string_of_bool b
  | V_Int i -> string_of_int i
  | V_Bigint s
  | V_BinaryString s
  | V_String s -> s
  | V_Enumerated (i, f) -> f i

  | V_BitString _ | V_IPv4 _ | V_List _ | V_Dict _
  | V_Unit | V_Function _ | V_Stream _ | V_OutChannel _
  | V_Module _ | V_Object _ ->
    raise (ContentError "String expected")

let string_of_type = function
  | V_Unit -> "unit"
  | V_Bool _ -> "bool"
  | V_Int _ -> "int"
  | V_Enumerated _ -> "enumerated"
  | V_String _ -> "string"
  | V_BinaryString _ -> "binary_string"
  | V_BitString _ -> "bit_string"
  | V_Bigint _ -> "big_int"
  | V_IPv4 _ -> "ipv4"
  | V_Function _ -> "function"  (* TODO: nature, arity? *)

  | V_List _ -> "list"
  | V_Dict d -> "dict"
  | V_Stream _ -> "stream"
  | V_OutChannel _ -> "outchannel"

  | V_Module _ -> "module"
  | V_Object (n, _ , _) -> n ^ "_object"



(* Environment handling *)

let rec getv env name = match env with
  | [] -> raise (NotFound name)
  | e::r -> begin
    try Hashtbl.find e name
    with Not_found -> getv r name
  end

let getv_str env name default =
  try
    eval_as_string (getv env name)
  with
    | NotFound _ | ContentError _ -> default

let getv_bool env name default =
  try
    eval_as_bool (getv env name)
  with
    | NotFound _ | ContentError _ -> default


let rec setv env name v = match env with
  | [] -> raise (NotFound name)
  | [e] -> Hashtbl.replace e name v
  | e::r ->
    if Hashtbl.mem e name
    then Hashtbl.replace e name v
    else setv r name v

let rec unsetv env name = match env with
  | [] -> raise (NotFound name)
  | e::r ->
    if Hashtbl.mem e name
    then Hashtbl.remove e name
    else unsetv r name



(* Native function helpers *)

let zero_value_fun f = function
  | [] -> f ()
  | _ -> raise WrongNumberOfArguments

let zero_value_fun_with_env f env = function
  | [] -> f env
  | _ -> raise WrongNumberOfArguments

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
  | [e1] -> V_Function (NativeFun (one_value_fun (f e1)))
  | _ -> raise WrongNumberOfArguments

let two_value_fun_with_env f env = function
  | [e1; e2] -> f env e1 e2
  | [e1] -> V_Function (NativeFunWithEnv (one_value_fun_with_env (fun env -> f env e1)))
  | _ -> raise WrongNumberOfArguments

let three_value_fun f = function
  | [e1; e2; e3] -> f e1 e2 e3
  | [e1; e2] -> V_Function (NativeFun (one_value_fun (f e1 e2)))
  | [e1] -> V_Function (NativeFun (two_value_fun (f e1)))
  | _ -> raise WrongNumberOfArguments

let three_value_fun_with_env f env = function
  | [e1; e2; e3] -> f env e1 e2 e3
  | [e1; e2] -> V_Function (NativeFunWithEnv (one_value_fun_with_env (fun env -> f env e1 e2)))
  | [e1] -> V_Function (NativeFunWithEnv (two_value_fun_with_env (fun env -> f env e1)))
  | _ -> raise WrongNumberOfArguments

let four_value_fun f = function
  | [e1; e2; e3; e4] -> f e1 e2 e3 e4
  | [e1; e2; e3] -> V_Function (NativeFun (one_value_fun (f e1 e2 e3)))
  | [e1; e2] -> V_Function (NativeFun (two_value_fun (f e1 e2)))
  | [e1] -> V_Function (NativeFun (three_value_fun (f e1)))
  | _ -> raise WrongNumberOfArguments

let five_value_fun f = function
  | [e1; e2; e3; e4; e5] -> f e1 e2 e3 e4 e5
  | [e1; e2; e3; e4] -> V_Function (NativeFun (one_value_fun (f e1 e2 e3 e4)))
  | [e1; e2; e3] -> V_Function (NativeFun (two_value_fun (f e1 e2 e3)))
  | [e1; e2] -> V_Function (NativeFun (three_value_fun (f e1 e2)))
  | [e1] -> V_Function (NativeFun (four_value_fun (f e1)))
  | _ -> raise WrongNumberOfArguments

let add_native name f =
  Hashtbl.replace global_env name (V_Function (NativeFun f))

let add_native_with_env name f =
  Hashtbl.replace global_env name (V_Function (NativeFunWithEnv f))
