open Types
open ParsingEngine


(* Generic param helpers *)

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

let no_getter () = raise Not_found
let no_setter _ = raise (ContentError ("Read-only field"))



(* ParserInterface and Module functor *)

module type ParserInterface = sig
  type t

  val name : string
  val params : (string * getter option * setter option) list

  val mk_ehf : unit -> error_handling_function 
  val parse : parsing_state -> t
  val dump : t -> string
  val enrich : t -> (string, value) Hashtbl.t -> unit
  val update : (string, value) Hashtbl.t -> t
  val to_string : t -> string
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
      then i else raise Not_found


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

  let equals (ref1, d1) (ref2, d2) =
    let i1 = find_index ref1
    and i2 = find_index ref2 in
    _update i1 d1;
    _update i2 d2;
    Hashtbl.find objects i1 = Hashtbl.find objects i2


  (* Object constructions *)

  let mk_pstate input = 
    let ehf = Parser.mk_ehf () in
    match input with
      | V_BinaryString s | V_String s -> pstate_of_string ehf s
      | V_Stream (name, s) -> pstate_of_stream ehf name s
      | _ -> raise (ContentError "String or stream expected")

  let parse input =
    let pstate = mk_pstate input in
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
    let pstate = mk_pstate input in
    let rec aux () =
      if eos pstate then []
      else
	try
	  (register (Parser.parse pstate))::(aux ())
	with
	  | OutOfBounds s ->
	    output_string stderr ("Out of bounds in " ^ s ^ "\n");
	    flush stderr;
	    []
	  | ParsingError (err, sev, pstate) ->
	    output_string stderr (string_of_parsing_error "Parsing error" err sev pstate);
	    flush stderr;
	    []
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
  let to_string_aux obj = V_String (Parser.to_string obj)

  let populate_param (param_name, getter, setter) =
    Hashtbl.replace param_getters param_name (Common.pop_option getter no_getter);
    Hashtbl.replace param_setters param_name (Common.pop_option setter no_setter)

  let populate_static_param (param_name, v) =
    Hashtbl.replace static_params param_name v

  let populate_fun (fun_name, f) =
    Hashtbl.replace static_params fun_name (V_Function (NativeFun (f)))

  let init () =
    List.iter populate_param Parser.params;
    populate_static_param ("name", V_String name);
    populate_param ("object_count", Some object_count, None);

    populate_fun ("parse", one_value_fun parse);
    populate_fun ("make", one_value_fun make);
    populate_fun ("dump", one_value_fun (apply dump_aux));
    populate_fun ("to_string", one_value_fun (apply to_string_aux));
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
    Hashtbl.replace param_getters param_name (Common.pop_option getter no_getter);
    Hashtbl.replace param_setters param_name (Common.pop_option setter no_setter)

  let populate_static_param (param_name, v) =
    Hashtbl.replace static_params param_name v

  let populate_fun (fun_name, f) =
    Hashtbl.replace static_params fun_name (V_Function (f))

  let init () =
    List.iter populate_param Library.params;
    populate_static_param ("name", V_String name);
    List.iter populate_fun Library.functions;
    ()

  type t = unit
  let register _ = raise NotImplemented
  let pop_object _ = raise NotImplemented
  let equals _ = raise NotImplemented
  let enrich _ = raise NotImplemented
  let update _ = raise NotImplemented
end
