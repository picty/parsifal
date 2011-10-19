open MapEval
open Common
open Asn1
open Asn1.Engine
open Asn1.Asn1EngineParams

module Asn1Module = struct
  type encoded_object = string

  (* Should be put in a meta module functor F *)
  let module_fields : (string, value) Hashtbl.t = Hashtbl.create 10 (*F*)
  let objects : (string, asn1_object) Hashtbl.t = Hashtbl.create 50 (*F*)
  let object_fields : (string, asn1_object -> value) Hashtbl.t = Hashtbl.create 40

  let add_object_field name f = Hashtbl.replace object_fields name f

  let init_module () =
    (* module fields *)
    Hashtbl.replace module_fields "tolerance" (V_Int 4);
    Hashtbl.replace module_fields "minDisplay" (V_Int 0);

    (* object fields *)
    add_object_field "class" (fun x -> V_String (string_of_class x.a_class));
    add_object_field "tag" (fun x -> V_Int (x.a_tag));
    add_object_field "tag_str" (fun x -> V_String (string_of_tag x.a_class x.a_tag));
    add_object_field "is_constructed" (fun x -> V_Bool (isConstructed x));
    let value_of_asn1_content raw o = match o.a_content with
      | Null
      | EndOfContents -> V_Unit
      | Boolean b -> V_Bool b
      | Integer i -> V_String (hexdump_int_list i)
      | BitString (_, s) -> V_String (if raw then s else hexdump s)
      | OId oid -> V_List (List.map (fun x -> V_Int x) (oid_expand oid))
      | Unknown s
      | String (s, true) -> V_String (if raw then s else hexdump s)
      | String (s, false) -> V_String s
      | Constructed objs -> V_List (List.map (fun x -> V_Asn1 x) objs)
    in
    add_object_field "content" (value_of_asn1_content false);
    add_object_field "content_raw" (value_of_asn1_content true);
    let extract_ohl = function
      | { a_ohl = None } -> raise Not_found
      | { a_ohl = Some t } -> t
    in
    add_object_field "offset" (fun x -> V_Int (fst3 (extract_ohl x)));
    add_object_field "hlen" (fun x -> V_Int (snd3 (extract_ohl x)));
    add_object_field "len" (fun x -> V_Int (trd3 (extract_ohl x)));;


(*  let _parse s =
    let asn1_ehf = default_error_handling_function
      (eval_as_int (Hashtbl.find module_fields "tolerance"))
      (eval_as_int (Hashtbl.find module_fields "minDisplay")) in
    let pstate = match s with
      | V_String s ->
	pstate_of_string asn1_ehf "(inline)" s
      | V_Stream (filename, s) ->
	pstate_of_stream asn1_ehf filename s
      | _ -> raise (ContentError "String or stream expected")
    in
    let res = parse pstate in
    Hashtbl.replace s res*)

  let _parse_str s =
    let asn1_ehf = default_error_handling_function
      (eval_as_int (Hashtbl.find module_fields "tolerance"))
      (eval_as_int (Hashtbl.find module_fields "minDisplay")) in
    let pstate = pstate_of_string asn1_ehf "(inline)" s in
    parse pstate

  let parse v = (*F, from a _parse function*) match v with
    | V_String s ->
      if not (Hashtbl.mem objects s) then begin
	let res = _parse_str s in
	Hashtbl.replace objects s res
      end;
      s
    | _ -> raise (ContentError "String expected")

  let get_obj s =
    if not (Hashtbl.mem objects s)
    then begin ignore (parse (V_String s)) end;
    Hashtbl.find objects s

  let dump s = s

  let print s =
    let o = get_obj s in
    (* TODO: Should be customizable *)
    let opts = { type_repr = PrettyType; data_repr = PrettyData;
		 resolver = Some X509.name_directory; indent_output = true } in
    string_of_object "" opts o

  let module_get field = Hashtbl.find module_fields field

  let get obj field =
    let o = get_obj obj in
    (Hashtbl.find object_fields field) o
end


let _ =
  Asn1Module.init_module ();
  (* module registering *)
  Hashtbl.replace module_table "asn1" ((module Asn1Module : MapModule));
  Hashtbl.replace global_env "asn1" (V_Module "asn1");;
