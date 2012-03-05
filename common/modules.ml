open Common
open Types
open ParsingEngine


(* Generic param helpers *)

let pstate_of_value_list input =
  let ehf = default_error_handling_function !tolerance !minDisplay in
  match input with
    | [name; V_BinaryString s | V_String s] -> _pstate_of_string ehf (Some (eval_as_string name)) s
    | [V_BinaryString s | V_String s] -> _pstate_of_string ehf None s
    | [V_Stream (name, s, _)] -> _pstate_of_stream ehf name s
    | _ -> raise (ContentError "String or stream expected")

let param_from_bool_ref name reference =
  (name,
   Some (fun () -> V_Bool !reference),
   Some (fun x -> reference := eval_as_bool (x)))

let param_from_int_ref name reference =
  (name,
   Some (fun () -> V_Int !reference),
   Some (fun x -> reference := eval_as_int (x)))

let param_from_string_ref name reference =
  (name,
   Some (fun () -> V_String !reference),
   Some (fun x -> reference := eval_as_string (x)))

let no_getter name () = raise (NotFound name)
let no_setter _ = raise (ContentError ("Read-only field"))



(* ParserInterface and Module functor *)

module type ParserInterface = sig
  type t

  val name : string
  val params : (string * getter option * setter option) list

  (* For the moment, we only work with EnvFuns *)
  val functions : (string * ((value -> t) * (t -> value) -> value list -> value) * int option) list

  val parse : parsing_state -> t
  val dump : t -> string
  val enrich : t -> (string, value) Hashtbl.t -> unit
  val update : (string, value) Hashtbl.t -> t
  val to_string : t -> string list
end;;



module MakeParserModule = functor (Parser : ParserInterface) -> struct
  type t = Parser.t
  let name = Parser.name
  let param_getters = Hashtbl.create 10
  let param_setters = Hashtbl.create 10
  let static_params = Hashtbl.create 10

  (* Object handling *)

  let count = ref 0
  let objects : (int, t) Hashtbl.t = Hashtbl.create 10
  let object_count () = V_Int (Hashtbl.length objects)

  let erase_obj = function
    | ObjectRef i -> Hashtbl.remove objects i

  let find_obj = function
    | ObjectRef i -> Hashtbl.find objects i

  let find_index = function
    | ObjectRef i ->
      if (Hashtbl.mem objects i)
      then i else raise (NotFound "Internal mayhem: object does not exist")


  let _register obj =
    let obj_ref = ObjectRef (!count) in
    Hashtbl.replace objects (!count) obj;
    Gc.finalise erase_obj obj_ref;
    incr count;
    obj_ref


  (* Operations on objects *)

  let register obj = V_Object (name, _register obj, Hashtbl.create 10)

  let enrich o d =
    if not (Hashtbl.mem d "@enriched") then begin
      Parser.enrich (find_obj o) d;
      Hashtbl.replace d "@enriched" V_Unit
    end

  let _update index d =
    if Hashtbl.mem d "@modified" then begin
      let new_obj = Parser.update d in
      Hashtbl.replace objects index new_obj;
      Hashtbl.remove d "@modified"
    end

  let update o d =
    let index = find_index o in
    _update index d

  let pop_object v =
    let (n, r, d) = eval_as_object v in
    if n <> name then raise (ContentError ("Foreign object"));
    let index = find_index r in
    _update index d;
    Hashtbl.find objects index

  let equals o1 o2 =
    let (_, ref1, d1) = eval_as_object o1
    and (_, ref2, d2) = eval_as_object o2 in
    let i1 = find_index ref1
    and i2 = find_index ref2 in
    _update i1 d1;
    _update i2 d2;
    V_Bool (Hashtbl.find objects i1 = Hashtbl.find objects i2)


  (* Object constructions *)

  let parse input =
    let pstate = pstate_of_value_list input in
    try
      register (Parser.parse pstate)
    with
      | OutOfBounds s ->
	output_string stderr ("Out of bounds in " ^ s ^ "\n");
	flush stderr;
	V_Unit
      | ParsingError (err, sev, pstate) ->
	output_string stderr (string_of_parsing_error "Parsing error" err sev pstate);
	flush stderr;
	V_Unit

  let parse_all input =
    let pstate = pstate_of_value_list input in
    let rec aux () =
      if eos pstate then []
      else
	try
	  let next = register (Parser.parse pstate) in
	  next::(aux ())
	with
	  | OutOfBounds s ->
	    output_string stderr ("Out of bounds in " ^ s ^ "\n");
	    flush stderr;
	    [V_Unit]
	  | ParsingError (err, sev, pstate) ->
	    output_string stderr (string_of_parsing_error "Parsing error" err sev pstate);
	    flush stderr;
	    [V_Unit]
    in aux ()
	      

    
  let make d =
    let dict = eval_as_dict d in
    let obj = Parser.update dict in
    Hashtbl.replace dict "@enriched" V_Unit;
    V_Object (name, _register obj, dict)


  (* Object export *)

  let apply f v =
    let (n, r, d) = eval_as_object v in
    if n <> name then raise (ContentError "Foreign object");
    let index = find_index r in
    _update index d;
    f (Hashtbl.find objects index)

  (* dump / to_string should be constructed with apply *)
  let dump_aux obj = V_BinaryString (Parser.dump obj)
  let to_string_aux obj = V_String (Common.cat (Parser.to_string obj))
  let to_string_indent_aux obj = V_List (List.map (fun x -> V_String x) (Parser.to_string obj))

  let populate_param (param_name, getter, setter) =
    Hashtbl.replace param_getters param_name (pop_option getter (no_getter param_name));
    Hashtbl.replace param_setters param_name (pop_option setter no_setter)

  let populate_static_param = Hashtbl.replace static_params

  let populate_fun (fun_name, f, nargs) =
    let real_f = f (pop_object, register) in
    match nargs with
      | None -> populate_static_param fun_name (V_Function (VargsFun real_f))
      | Some n -> populate_static_param fun_name (V_Function (SimpleFun (n, [], real_f)))

  let init () =
    List.iter populate_param Parser.params;
    populate_static_param "name" (V_String name);
    populate_param ("object_count", Some object_count, None);

    populate_static_param "parse" (V_Function (VargsFun parse));
    populate_static_param "make" (one_value_fun make);
    populate_static_param "dump" (one_value_fun (apply dump_aux));
    populate_static_param "to_string" (one_value_fun (apply to_string_aux));
    populate_static_param "to_string_indent" (one_value_fun (apply to_string_indent_aux));
    List.iter populate_fun Parser.functions;
    ()

    (* TODO: Add a _dict or _params magic objects ? Remove all _ ? *)

end





(* Library Modules *)

module type LibraryInterface = sig
  val name : string
  val params : (string * getter option * setter option) list
  val functions : (string * function_sort) list
end;;


module MakeLibraryModule = functor (Library : LibraryInterface) -> struct
  let name = Library.name
  let param_getters = Hashtbl.create 10
  let param_setters = Hashtbl.create 10
  let static_params = Hashtbl.create 10

  let populate_param (param_name, getter, setter) =
    Hashtbl.replace param_getters param_name (pop_option getter (no_getter param_name));
    Hashtbl.replace param_setters param_name (pop_option setter no_setter)

  let populate_static_param (param_name, v) =
    Hashtbl.replace static_params param_name v

  let populate_fun (fun_name, f) =
    Hashtbl.replace static_params fun_name (V_Function (f))

  let init () =
    List.iter populate_param Library.params;
    populate_static_param ("name", V_String name);
    List.iter populate_fun Library.functions;
    ()
end




(* Parsing Lib *)
module ParserLib = struct
  let name = "parser"
  let params = [
    param_from_int_ref "tolerance" tolerance;
    param_from_int_ref "minDisplay" minDisplay;
  ]
  let functions = []
end

module ParserModule = MakeLibraryModule (ParserLib)
let _ = add_library_module ((module ParserModule : Module))
