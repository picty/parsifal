open Common
open Types
open Modules
open ParsingEngine

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


module BinaryRecord = struct
  type parse_function = parsing_state -> value
  type dump_function = value -> string
  type parsing_constraint = string * parse_function * dump_function
  type description = parsing_constraint list

  let parse desc pstate =
    let res = Hashtbl.create (List.length desc) in
    let rec parse_aux = function
      | [] -> res
      | (name, parse_fun, _)::r ->
	let v = parse_fun pstate in
	Hashtbl.add res name v;
	parse_aux r
    in parse_aux desc

  let dump desc dict =
    let rec dump_aux = function
      | [] -> ""
      | (name, _, dump_fun)::r ->
	let v = hash_find dict name in
	(dump_fun v) ^ (dump_aux r)
    in dump_aux desc

  let enrich desc o (d : (string, value) Hashtbl.t) =
    let enrich_aux (n, _, _) = Hashtbl.replace d n (Hashtbl.find o n) in
    List.iter enrich_aux desc

  let update desc (d : (string, value) Hashtbl.t) =
    let n_fields = List.length (desc) in
    let new_obj = Hashtbl.create n_fields in
    let update_aux (n, _, _) = Hashtbl.replace new_obj n (hash_find d n) in
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

  let to_string o = Printer.PrinterLib._string_of_value (Some name) true (V_Dict o)
end
