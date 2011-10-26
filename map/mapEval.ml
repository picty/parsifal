open MapLang

(* Value and environment handling *)

module StringSet = Set.Make (String);;

type object_ref = ObjectRef of string * int;;


type function_sort =
  | NativeFun of (value list -> value)
  | NativeFunWithEnv of (environment -> value list -> value)
  | InterpretedFun of (environment * string list * expression list)

and value =
  | V_Unit
  | V_Bool of bool
  | V_Int of int
  | V_String of string
  | V_BinaryString of string
  | V_BitString of int * string
  | V_Bigint of string
  | V_Function of function_sort

  | V_List of value list
  | V_Set of StringSet.t
  | V_Dict of (string, value) Hashtbl.t
  | V_ValueDict of (value, value) Hashtbl.t
  | V_Stream of string * char Stream.t
  | V_OutChannel of string * out_channel
  | V_Lazy of value lazy_t

  | V_Module of string * (string, value) Hashtbl.t
  | V_Object of object_ref * (string, value) Hashtbl.t

  | V_TlsRecord of Tls.record
  | V_Certificate of X509.certificate

and environment = (string, value) Hashtbl.t list

let global_env : (string, value) Hashtbl.t = Hashtbl.create 100


module type MapModule = sig
  val name : string
  val params : (string, value) Hashtbl.t

  val init : unit -> unit
  val parse : string -> char Stream.t -> object_ref
  val make : (string, value) Hashtbl.t -> object_ref
  val enrich : object_ref -> (string, value) Hashtbl.t -> unit
  val update : object_ref -> (string, value) Hashtbl.t -> unit
  val dump : object_ref -> string
  val to_string : object_ref -> string
end

let modules : (string, (module MapModule)) Hashtbl.t = Hashtbl.create 10

let add_module m =
  let module M = (val m : MapModule) in
  M.init ();
  Hashtbl.replace modules M.name m;
  Hashtbl.replace global_env M.name (V_Module (M.name, M.params))


let certificate_field_access : (string, X509.certificate -> value) Hashtbl.t = Hashtbl.create 40
let tls_field_access : (string, Tls.record -> value) Hashtbl.t = Hashtbl.create 40


exception NotImplemented
exception WrongNumberOfArguments
exception ContentError of string

exception ReturnValue of value
exception Continue
exception Break


type display_opts = {
  raw_display : bool;
  separator : string;
  after_opening : string;
  before_closing : string;
  new_eval : value -> string
}

let eval_as_int = function
  | V_Int i -> i
  | V_String s
  | V_BinaryString s -> int_of_string s
  | V_Bigint _ -> raise NotImplemented
  | _ -> raise (ContentError "Integer expected")

let eval_as_bool = function
  | V_Bool b -> b
  | V_Unit | V_Int 0 | V_List [] -> false
  | V_Int _ | V_List _ -> true
  | V_Set s -> StringSet.is_empty s
  | V_String s
  | V_BinaryString s
  | V_BitString (_, s) -> (String.length s) <> 0
  | V_Bigint s -> (String.length s) > 0 && s.[0] != '\x00'
  | V_Stream (_, s) -> not (Common.eos s)
  | V_Dict d -> (Hashtbl.length d) <> 0
  | V_ValueDict d -> (Hashtbl.length d) <> 0
  | V_Object _ -> true

  | V_TlsRecord _ | V_Certificate _ -> true

  | _ -> raise (ContentError "Boolean expected")

let eval_as_function = function
  | V_Function f -> f
  | _ -> raise (ContentError "Function expected")

let eval_as_stream = function
  | V_Stream (n, s) -> n, s
  | _ -> raise (ContentError "Function expected")

let eval_as_dict = function
  | V_Dict d -> d
  | _ -> raise (ContentError "Dictionary expected")

let eval_as_list = function
  | V_List l -> l
  | _ -> raise (ContentError "List expected")

let strict_eval_value = function
  | V_Lazy lazyval -> Lazy.force lazyval
  | v -> v

let rec string_of_type = function
  | V_Unit -> "unit"
  | V_Bool _ -> "bool"
  | V_Int _ -> "int"
  | V_String _ -> "string"
  | V_BinaryString _ -> "binary_string"
  | V_BitString _ -> "bit_string"
  | V_Bigint _ -> "big_int"
  | V_Function _ -> "function"  (* TODO: nature, arity? *)

  | V_List _ -> "list"
  | V_Set _ -> "set"
  | V_Dict d -> "dict"
  | V_ValueDict _ -> "value_dict"
  | V_Stream _ -> "stream"
  | V_OutChannel _ -> "outchannel"
  | V_Lazy lazyval ->
    if Lazy.lazy_is_val lazyval
    then (string_of_type (Lazy.force lazyval)) else "lazy"

  | V_Module _ -> "module"
  | V_Object (ObjectRef (n, _), _) -> n ^ "_object"

  | V_TlsRecord _ -> "TLSrecord"
  | V_Certificate _ -> "certificate"

and eval_as_string = function
  | V_Bool b -> string_of_bool b
  | V_Int i -> string_of_int i
  | V_Bigint s
  | V_BinaryString s
  | V_String s -> s

  | V_BitString _ | V_List _ | V_Set _ | V_Dict _ | V_ValueDict _
  | V_TlsRecord _ | V_Certificate _
  | V_Unit | V_Function _ | V_Stream _ | V_OutChannel _
  | V_Lazy _ | V_Module _ | V_Object _ ->
    raise (ContentError "String expected")


and string_of_value_i env current_indent v =
  let get_dopts () =
    let raw_display = getv_bool env "_raw_display" false in
    let indent = getv_str env "_indent" "" in
    let multiline = (String.length indent) > 0 in
    if multiline then begin
      let new_indent = current_indent ^ indent in
      { raw_display = raw_display;
        separator = (getv_str env "_separator" ",") ^ "\n" ^ new_indent;
	after_opening = "\n" ^ new_indent; before_closing = "\n" ^ current_indent;
	new_eval = string_of_value_i env new_indent }
    end else
      { raw_display = raw_display;
	separator = getv_str env "_separator" ", ";
	after_opening = ""; before_closing = "";
	new_eval = string_of_value_i env "" }
  in

  match v with
    | V_Bool b -> string_of_bool b
    | V_Int i -> string_of_int i
    | V_String s -> s
    | V_BinaryString s -> "\"" ^ (Common.hexdump s) ^ "\""
    | V_BitString (n, s) -> "\"[" ^ (string_of_int n) ^ "]" ^ (Common.hexdump s) ^ "\""
    | V_Bigint s -> "0x" ^ (Common.hexdump s)

    | V_List [] -> "[]"
    | V_Set s when (StringSet.is_empty s) -> "{}"
    | V_Dict d when (Hashtbl.length d = 0) -> "{}"
    | V_ValueDict d when (Hashtbl.length d = 0) -> "{}"

    | V_List l ->
      let dopts = get_dopts () in
      "[" ^ dopts.after_opening ^
	(String.concat dopts.separator (List.map dopts.new_eval l)) ^
	dopts.before_closing ^ "]"
    | V_Set s ->
      let dopts = get_dopts () in
      "{" ^ dopts.after_opening ^
	(String.concat dopts.separator (StringSet.elements s)) ^
	dopts.before_closing ^ "}"
    | V_Dict d ->
      let dopts = get_dopts () in
      let hash_aux k v accu =
	if dopts.raw_display || ((String.length k > 0) && (k.[0] != '_'))
	then (k ^ " -> " ^ (dopts.new_eval v))::accu
	else accu
      in
      "{" ^ dopts.after_opening ^
	(String.concat dopts.separator (Hashtbl.fold hash_aux d [])) ^
	dopts.before_closing ^ "}"
    | V_ValueDict d ->
      let dopts = get_dopts () in
      let hash_aux k v accu =
	((dopts.new_eval k) ^ " -> " ^ (dopts.new_eval v))::accu
      in
      "{" ^ dopts.after_opening ^
	(String.concat dopts.separator (Hashtbl.fold hash_aux d [])) ^
	dopts.before_closing ^ "}"

    | V_TlsRecord r -> Tls.string_of_record r
    | V_Certificate c -> X509.string_of_certificate true "" (Some X509.name_directory) c

    | V_Object (ObjectRef (n, _) as obj_ref, d) ->
      if getv_bool env "_raw_display" false then begin
	if not (Hashtbl.mem d "@enriched") then begin
	  let module M = (val (Hashtbl.find modules n) : MapModule) in
	  M.enrich obj_ref d;
	  Hashtbl.replace d "@enriched" V_Unit
	end;
	string_of_value_i env current_indent (V_Dict d)
      end else begin
	let module M = (val (Hashtbl.find modules n) : MapModule) in
	if Hashtbl.mem d "@modified" then begin
	  M.update obj_ref d;
	  Hashtbl.remove d "@modified"
	end;
	M.to_string obj_ref
      end

    | (V_Unit | V_Function _ | V_Stream _ | V_OutChannel _
	  | V_Lazy _ | V_Module _) as v -> "<" ^ (string_of_type v) ^ ">"

and getv env name = match env with
  | [] -> raise Not_found
  | e::r -> begin
    try
      strict_eval_value (Hashtbl.find e name)
    with
      | Not_found -> getv r name
  end

and getv_str env name default =
  try
    eval_as_string (getv env name)
  with
    | Not_found | ContentError _ -> default

and getv_bool env name default =
  try
    eval_as_bool (getv env name)
  with
    | Not_found | ContentError _ -> default

let rec setv env name v = match env with
  | [] -> raise Not_found
  | [e] -> Hashtbl.replace e name v
  | e::r ->
    if Hashtbl.mem e name
    then Hashtbl.replace e name v
    else setv r name v

let rec unsetv env name = match env with
  | [] -> raise Not_found
  | e::r ->
    if Hashtbl.mem e name
    then Hashtbl.remove e name
    else unsetv r name

let string_of_value env v = string_of_value_i env "" v


(* Interpretation *)

let rec  eval_string_token env = function
  | ST_String s -> s
  | ST_Var s -> eval_as_string (getv env s)
  | ST_Expr s -> eval_as_string (interpret_string env s)

and eval_exp env exp =
  let eval = eval_exp env in
  match exp with
    | E_Bool b -> V_Bool b
    | E_Int i -> V_Int i
    | E_String l -> V_String (String.concat "" (List.map (eval_string_token env) l))
    | E_Var s -> getv env s

    | E_Concat (a, b) -> begin
      match eval a, eval b with
	| V_BinaryString s1, v2 -> V_BinaryString (s1 ^ (eval_as_string v2))
	| v1, V_BinaryString s2 -> V_BinaryString ((eval_as_string v1) ^ s2)
	| v1, v2 -> V_String ((eval_as_string v1) ^ (eval_as_string v2))
    end
    | E_Plus (a, b) -> V_Int ((eval_as_int (eval a)) + (eval_as_int (eval b)))
    | E_Minus (a, b) -> V_Int (eval_as_int (eval a) - eval_as_int (eval b))
    | E_Mult (a, b) -> V_Int (eval_as_int (eval a) * eval_as_int (eval b))
    | E_Div (a, b) -> V_Int (eval_as_int (eval a) / eval_as_int (eval b))
    | E_Mod (a, b) -> V_Int (eval_as_int (eval a) mod eval_as_int (eval b))

    | E_Equal (a, b) -> V_Bool (eval_equality env (eval a) (eval b))
    | E_Lt (a, b) -> V_Bool (match eval a, eval b with
	| V_Int i1, V_Int i2 -> i1 < i2
	| V_Bigint _, V_Bigint _ -> raise NotImplemented
	| v1, v2 -> eval_as_string v1 < eval_as_string v2
    )
    | E_In (a, b) -> V_Bool (eval_in env (eval a) (eval b))

    | E_Like (a, b) ->
      V_Bool (Str.string_match (Str.regexp (eval_as_string (eval b)))
		(eval_as_string (eval a)) 0)

    | E_LAnd (a, b) -> V_Bool (eval_as_bool (eval a) && eval_as_bool (eval b))
    | E_LOr (a, b) -> V_Bool (eval_as_bool (eval a) || eval_as_bool (eval b))
    | E_LNot e -> V_Bool (not (eval_as_bool (eval e)))

    | E_BAnd (a, b) -> V_Int (eval_as_int (eval a) land eval_as_int (eval b))
    | E_BOr (a, b) -> V_Int (eval_as_int (eval a) lor eval_as_int (eval b))
    | E_BXor (a, b) -> V_Int (eval_as_int (eval a) lxor eval_as_int (eval b))
    | E_BNot e -> V_Int (lnot (eval_as_int (eval e)))

    | E_Exists e -> begin
      try
	ignore (eval e);
	V_Bool true
      with Not_found -> V_Bool false
    end

    | E_Function (arg_names, e) ->
      let na = List.length arg_names in
      let new_env = Hashtbl.create (2 * na) in
      V_Function (InterpretedFun (new_env::env, arg_names, e))
    | E_Local ids ->
      let rec add_locals ids =
	match env, ids with
	  | _, [] -> V_Unit
	  | [], _ -> raise Not_found
	  | e::_, id::r ->
	    Hashtbl.replace e id V_Unit;
	    add_locals r
      in
      add_locals ids
    | E_Apply (e, args) -> begin
      let f_value = eval_as_function (eval e) in
      let arg_values = List.map eval args in
      eval_function env f_value arg_values
    end
    | E_Return (Some e) -> raise (ReturnValue (eval e))
    | E_Return None -> raise (ReturnValue V_Unit)

    | E_List e -> V_List (List.map eval e)
    | E_Cons (e1, e2) -> V_List ((eval e1)::(eval_as_list (eval e2)))

    | E_GetField (e, f) -> get_field (eval e) f
    | E_SetField (e, f, v) -> set_field false (eval e) f (eval v)

    | E_Assign (var, e) ->
      setv env var (eval e);
      V_Unit
    | E_Unset (var) ->
      unsetv env var;
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

and eval_function env f args = match f with
  | NativeFun f -> f args
  | NativeFunWithEnv f -> f env args
  | InterpretedFun (saved_env::r, arg_names, body) ->
    let local_env = Hashtbl.copy saved_env in
    let rec instanciate_and_eval = function
      | [], [] -> begin
	try
	  eval_exps (local_env::r) body
	with
	  | ReturnValue v -> v
      end
      | remaining_names, [] ->
	V_Function (InterpretedFun (local_env::r, remaining_names, body))
      | name::names, value::values ->
	Hashtbl.replace local_env name value;
	instanciate_and_eval (names, values)
      | _ -> raise WrongNumberOfArguments
    in instanciate_and_eval (arg_names, args)
  | InterpretedFun _ -> failwith "eval_function called on an InterpretedFun with an empty saved_environment"

and eval_equality env a b =
  let rec equal_list = function
    | [], [] -> true
    | va::ra, vb::rb ->
      (eval_equality env va vb) && (equal_list (ra, rb))
    | _ -> false
  in
  match a, b with
    | V_Unit, V_Unit -> true
    | V_Bool b1, V_Bool b2 -> b1 = b2
    | V_Int i1, V_Int i2 -> i1 = i2
    | V_BitString (n1, s1), V_BitString (n2, s2) -> n1 = n2 && s1 = s2

    | V_List l1, V_List l2 -> equal_list (l1, l2)
    | V_Set s1, V_Set s2 -> StringSet.compare s1 s2 = 0

    (* TODO *)
    | V_Dict d1, V_Dict d2 -> raise NotImplemented
    | V_ValueDict d1, V_ValueDict d2 -> raise NotImplemented
    | V_Module _, V_Module _ | V_Object _, V_Object _ -> raise NotImplemented

    | V_TlsRecord r1, V_TlsRecord r2 -> r1 = r2
    | V_Certificate c1, V_Certificate c2 -> c1 = c2

    | v1, v2 ->
      eval_as_string v1 = eval_as_string v2

and eval_in env a b =
  let rec eval_in_list = function
    | [] -> false
    | v::r -> (eval_equality env a v) || (eval_in_list r)
  in
  match b with
    | V_List l -> eval_in_list l
    | V_Set s -> StringSet.mem (eval_as_string a) s
    | _ -> raise (ContentError "List or set expected")


and eval_exps env = function
  | [] -> V_Unit
  | [e] -> eval_exp env e
  | e::r ->
    ignore (eval_exp env e);
    eval_exps env r

and interpret_string env s =
  let lexbuf = Lexing.from_string s in
  let ast = MapParser.exprs MapLexer.main_token lexbuf in
  eval_exps env ast

and get_field e f =
  strict_eval_value (match e with
    | V_Dict d -> (Hashtbl.find d f)
    | V_ValueDict d -> (Hashtbl.find d (V_String f))
    | V_Certificate c -> (Hashtbl.find certificate_field_access f) c
    | V_TlsRecord r -> (Hashtbl.find tls_field_access f) r

    | V_Module (_, d) ->
      if f = "_dict" then V_Dict d else (Hashtbl.find d f)

    | V_Object (ObjectRef (n, _) as obj_ref, d) ->
      if not (Hashtbl.mem d "@enriched") then begin
	let module M = (val (Hashtbl.find modules n) : MapModule) in
	M.enrich obj_ref d;
	Hashtbl.replace d "@enriched" V_Unit
      end;
      if f = "_dict" then V_Dict d else (Hashtbl.find d f)

    | _ -> raise (ContentError ("Object with fields expected"))
  )

and get_field_all e f =
  strict_eval_value (match e with
    | V_Dict d -> V_List (Hashtbl.find_all d f)
    | V_ValueDict d -> V_List (Hashtbl.find_all d (V_String f))

    | V_Module (_, d) ->
      if f = "_dict" then V_List ([V_Dict d]) else V_List (Hashtbl.find_all d f)

    | V_Object (ObjectRef (n, _) as obj_ref, d) ->
      if not (Hashtbl.mem d "@enriched") then begin
	let module M = (val (Hashtbl.find modules n) : MapModule) in
	M.enrich obj_ref d;
	Hashtbl.replace d "@enriched" V_Unit
      end;
      if f = "_dict" then V_List ([V_Dict d]) else V_List (Hashtbl.find_all d f)

    | _ -> raise (ContentError ("Object with fields expected"))
  )

and set_field append e f v =
  let add_function = if append then Hashtbl.add else Hashtbl.replace in
  begin
    match e with
      | V_Dict d -> (add_function d f v)
      | V_ValueDict d -> (add_function d (V_String f) v)

      | V_Module (_, d) ->
	if f = "_dict" then raise (ContentError ("Read-only field"));
	(add_function d f v)
      | V_Object (ObjectRef (n, _) as obj_ref, d) ->
	if f = "_dict" then raise (ContentError ("Read-only field"));
	if not (Hashtbl.mem d "@enriched") then begin
	  let module M = (val (Hashtbl.find modules n) : MapModule) in
	  M.enrich obj_ref d;
	  Hashtbl.replace d "@enriched" V_Unit
	end;
	add_function d f v;
	Hashtbl.replace d "@modified" V_Unit

      | _ -> raise (ContentError ("Object with mutable fields expected"))
  end;
  V_Unit

and unset_field e f =
  begin
    match e with
      | V_Dict d -> (Hashtbl.remove d f)
      | V_ValueDict d -> (Hashtbl.remove d (V_String f))

      | V_Module (_, d) ->
	if f = "_dict" then raise (ContentError ("Read-only field"));
	(Hashtbl.remove d f)
      | V_Object (ObjectRef (n, _) as obj_ref, d) ->
	if f = "_dict" then raise (ContentError ("Read-only field"));
	if not (Hashtbl.mem d "@enriched") then begin
	  let module M = (val (Hashtbl.find modules n) : MapModule) in
	  M.enrich obj_ref d;
	  Hashtbl.replace d "@enriched" V_Unit
	end;
	Hashtbl.remove d f;
	Hashtbl.replace d "@modified" V_Unit

      | _ -> raise (ContentError ("Object with mutable fields expected"))
  end;
  V_Unit
