open MapEval

module type ParserInterface = sig
  type t
  val name : string
  val params : (string, value) Hashtbl.t

  val init : unit -> unit
  val parse : string -> char Stream.t -> t
  val dump : t -> string
  val enrich : t -> (string, value) Hashtbl.t -> unit
  val update : (string, value) Hashtbl.t -> t
  val to_string : t -> string
end;;



module Make = functor (Parser : ParserInterface) -> struct
  type t = Parser.t
  let name = Parser.name
  let params = Parser.params

  let count = ref 0
  let objects : (int, t) Hashtbl.t = Hashtbl.create 10
  let object_count = function
    | [] -> V_Int (Hashtbl.length objects)
    | _ -> raise WrongNumberOfArguments


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
    Parser.init ();
    Hashtbl.replace params "_object_count" (V_Function (NativeFun object_count))

  let _register obj =
    let obj_ref = ObjectRef (name, !count) in
    Hashtbl.replace objects (!count) obj;
    Gc.finalise erase_obj obj_ref;
    incr count;
    obj_ref

  let register obj = V_Object (_register obj, Hashtbl.create 10)

  let parse stream_name stream =
    let obj = Parser.parse stream_name stream in
    register obj
    
  let make d =
    let obj = Parser.update d in
    _register obj

  let enrich o d = Parser.enrich (find_obj o) d

  let update o d =
    let index = find_index o in
    let new_obj = Parser.update d in
    Hashtbl.replace objects index new_obj

  let dump o = Parser.dump (find_obj o)
  let to_string o = Parser.to_string (find_obj o)

end
