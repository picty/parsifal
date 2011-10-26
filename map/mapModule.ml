open MapEval

type 'a enricher = {
  to_bool : bool -> 'a;
  to_int : int -> 'a;
  to_string : string -> 'a;
  to_binary_string : string -> 'a;
  to_list : 'a list -> 'a;

  of_bool : 'a -> bool;
  of_int : 'a -> int;
  of_string : 'a -> string;
  of_binary_string : 'a -> string;
  of_list : 'a -> 'a list;
};;

module type ParserInterface = sig
  type t
  val name : string
  val default_tolerance : int
  val default_minDisplay : int

  val parse : int -> int -> string -> char Stream.t -> t
  val dump : t -> string
  val enrich : 'a enricher -> t -> (string, 'a) Hashtbl.t -> unit
  val update : 'a enricher -> (string, 'a) Hashtbl.t -> t
  val to_string : t -> string
end;;



let value_enricher : value enricher = {
  to_bool = (fun b -> V_Bool b);
  to_int = (fun i -> V_Int i);
  to_string = (fun s -> V_String s);
  to_binary_string = (fun s -> V_BinaryString s);
  to_list = (fun l -> V_List l);

  of_bool = eval_as_bool;
  of_int = eval_as_int;
  of_string = eval_as_string;
  of_binary_string = eval_as_string;
  of_list = eval_as_list;
}

module Make = functor (Parser : ParserInterface) -> struct
  type t = Parser.t
  let name = Parser.name
  let params : (string, value) Hashtbl.t = Hashtbl.create 10

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
    Hashtbl.replace params "_tolerance" (V_Int (Parser.default_tolerance));
    Hashtbl.replace params "_minDisplay" (V_Int (Parser.default_minDisplay));
    Hashtbl.replace params "_dict" (V_Dict params);
    Hashtbl.replace params "_object_count" (V_Function (NativeFun object_count))

  let add_new_object obj =
    let obj_ref = ObjectRef (name, !count) in
    Hashtbl.replace objects (!count) obj;
    Gc.finalise erase_obj obj_ref;
    incr count;
    obj_ref

  let parse stream_name stream =
    let tolerance = eval_as_int (Hashtbl.find params "_tolerance")
    and minDisplay = eval_as_int (Hashtbl.find params "_minDisplay") in
    let obj = Parser.parse tolerance minDisplay stream_name stream in
    add_new_object obj
    
  let make d =
    let obj = Parser.update value_enricher d in
    add_new_object obj

  let enrich o d = Parser.enrich value_enricher (find_obj o) d

  let update o d =
    let index = find_index o in
    let new_obj = Parser.update value_enricher d in
    Hashtbl.replace objects index new_obj

  let dump o = Parser.dump (find_obj o)
  let to_string o = Parser.to_string (find_obj o)

end
