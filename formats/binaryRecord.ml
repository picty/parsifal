open Common
open Types
open Modules
open ParsingEngine
open Printer

let parse_uint8 = lift_int pop_uint8
let dumpv_uint8 value = String.make 1 (char_of_int (eval_as_int value land 0xff))

let parse_uint16 = lift_int pop_uint16
let dumpv_uint16 value =
  let int_val = eval_as_int value in
  let res = String.make 2 (char_of_int (int_val land 0xff)) in
  res.[0] <- char_of_int ((int_val lsr 8) land 0xff);
  res

let parse_string n = lift_string (pop_fixedlen_string n)
let parse_bin_string n = lift_bin_string (pop_fixedlen_string n)
let parse_varlen_string len_fun = lift_string (pop_varlen_string len_fun)
let parse_varlen_bin_string len_fun = lift_bin_string (pop_varlen_string len_fun)
let parse_ipv4 = lift_ipv4 (pop_fixedlen_string 4)

let dump_varlen_string dump_len value =
  let content_str = eval_as_string value in
  let n = String.length content_str in
  (dump_len n) ^ content_str

let dump_varlen_list dump_len dump_content value =
  let content_str = String.concat "" (List.map dump_content (eval_as_list value)) in
  let n = String.length content_str in
  (dump_len n) ^ content_str


let raw_hex = Some (fun v -> V_String (hexdump (eval_as_string v)))
let hex_int n = Some (fun v -> V_String (hexdump_int_n n (eval_as_int v)))
let hex_int_list n =
  Some (fun v -> V_List (List.map (fun x -> V_String (hexdump_int_n n (eval_as_int x))) (eval_as_list v)))

module BinaryRecord = struct
  type parse_function = parsing_state -> value
  type dump_function = value -> string
  type tostring_function = value -> value

  type parsing_constraint = {
    pc_name : string;
    pc_parse : parse_function;
    pc_dump : dump_function;
    pc_tostring : tostring_function
  }
  type description = parsing_constraint list

  let rec mk_desc = function
    | [] -> []
    | (n, p, d, None)::r ->
      {pc_name = n; pc_parse = p; pc_dump = d; pc_tostring = Common.identity}::(mk_desc r)
    | (n, p, d, Some tr)::r ->
      {pc_name = n; pc_parse = p; pc_dump = d; pc_tostring = tr}::(mk_desc r)

  let parse desc pstate =
    let res = Hashtbl.create (List.length desc) in
    let rec parse_aux = function
      | [] -> res
      | cons::r ->
	let v = cons.pc_parse pstate in
	Hashtbl.add res cons.pc_name v;
	parse_aux r
    in parse_aux desc

  let dump desc dict =
    let rec dump_aux = function
      | [] -> ""
      | cons::r ->
	let v = hash_find dict cons.pc_name in
	(cons.pc_dump v) ^ (dump_aux r)
    in dump_aux desc

  let to_string title desc dict =
    let rec to_string_aux = function
      | [] -> []
      | cons::r ->
	let v = hash_find dict cons.pc_name in
	let v_str = PrinterLib._string_of_value (Some cons.pc_name) false (cons.pc_tostring v) in
	v_str::(to_string_aux r)
    in
    let content, _ = PrinterLib.flatten_strlist (to_string_aux desc) in
    PrinterLib._string_of_strlist title (list_options !PrinterLib.separator true) content

  let enrich desc o (d : (string, value) Hashtbl.t) =
    let enrich_aux cons = Hashtbl.replace d cons.pc_name (Hashtbl.find o cons.pc_name) in
    List.iter enrich_aux desc

  let update desc (d : (string, value) Hashtbl.t) =
    let n_fields = List.length (desc) in
    let new_obj = Hashtbl.create n_fields in
    let update_aux cons = Hashtbl.replace new_obj cons.pc_name (hash_find d cons.pc_name) in
    List.iter update_aux (desc);
    new_obj
end


module type BinaryRecordInterface = sig
  val name : string
  val description : BinaryRecord.description
end

module MakeBinaryRecordParserInterface = functor (Interface : BinaryRecordInterface) -> struct
  type t = (string, value) Hashtbl.t
  let name = Interface.name
  let params = []
  let functions = []

  let parse = BinaryRecord.parse Interface.description
  let dump = BinaryRecord.dump Interface.description
  let enrich = BinaryRecord.enrich Interface.description
  let update = BinaryRecord.update Interface.description

  let to_string o =
    if !PrinterLib.raw_display
    then PrinterLib._string_of_value (Some name) true (V_Dict o)
    else BinaryRecord.to_string (Some name) Interface.description o
end
