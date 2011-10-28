open MapEval

module type ParserInterface = sig
  type t
  val name : string
  val params : (string * getter option * setter option) list

  val parse : string -> char Stream.t -> t option
  val dump : t -> string
  val enrich : t -> (string, value) Hashtbl.t -> unit
  val update : (string, value) Hashtbl.t -> t
  val to_string : t -> string
end;;


let param_from_bool_ref name reference =
  (name,
   Some (fun () -> V_Bool !reference),
   Some (fun x -> reference := eval_as_bool (x)))

let param_from_int_ref name reference =
  (name,
   Some (fun () -> V_Int !reference),
   Some (fun x -> reference := eval_as_int (x)))

module Make = functor (Parser : ParserInterface) -> struct
  type t = Parser.t
  let name = Parser.name
  let param_getters = Hashtbl.create 10
  let param_setters = Hashtbl.create 10

  let count = ref 0
  let objects : (int, t) Hashtbl.t = Hashtbl.create 10
  let object_count () = V_Int (Hashtbl.length objects)


  let erase_obj = function
    | ObjectRef (n, i) ->
      if (name = n)
      then Hashtbl.remove objects i
      else failwith ("erase_obj called on a foreign object (" ^
			n ^ " instead of " ^ name ^ ")")

  let find_obj = function
    | ObjectRef (n, i) ->
      if (name = n)
      then Hashtbl.find objects i
      else raise Not_found

  let find_index = function
    | ObjectRef (n, i) ->
      if (name = n) && (Hashtbl.mem objects i)
      then i else raise Not_found


  let init () =
    let no_getter () = raise Not_found in
    let no_setter _ = raise (ContentError ("Read-only field")) in
    let populate_param (param_name, getter, setter) =
      Hashtbl.replace param_getters param_name (Common.pop_option getter no_getter);
      Hashtbl.replace param_setters param_name (Common.pop_option setter no_setter);
    in
    List.iter populate_param Parser.params;
    populate_param ("_name", Some (fun () -> V_String name), None);
    populate_param ("_object_count", Some object_count, None)
    (* TODO: Add a _dict or _params magic objects ? Remove all _ ? *)


  let _register obj =
    let obj_ref = ObjectRef (name, !count) in
    Hashtbl.replace objects (!count) obj;
    Gc.finalise erase_obj obj_ref;
    incr count;
    obj_ref

  let register obj = V_Object (_register obj, Hashtbl.create 10)

  let parse stream_name stream =
    match Parser.parse stream_name stream with
      | None -> V_Unit
      | Some obj -> register obj
    
  let make d =
    let obj = Parser.update d in
    _register obj


  let equals o1 o2 =
    let x1 = find_obj o1
    and x2 = find_obj o2 in
    x1 = x2

  let enrich o d = Parser.enrich (find_obj o) d

  let update o d =
    let index = find_index o in
    let new_obj = Parser.update d in
    Hashtbl.replace objects index new_obj

  let dump o = Parser.dump (find_obj o)
  let to_string o = Parser.to_string (find_obj o)

end
