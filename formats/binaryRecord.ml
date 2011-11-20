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
  let n_fields = List.length (Interface.description)

  let parse = BinaryRecord.parse Interface.description

  let dump = BinaryRecord.dump Interface.description

  let enrich o d =
    Hashtbl.replace d "@name" (V_String name);
    let enrich_aux (n, _, _) = Hashtbl.replace d n (Hashtbl.find o n) in
    List.iter enrich_aux (Interface.description)

  let update d =
    let new_obj = Hashtbl.create n_fields in
    let update_aux (n, _, _) = Hashtbl.replace new_obj n (hash_find d n) in
    List.iter update_aux (Interface.description);
    new_obj

  let to_string o = Printer.PrinterLib._string_of_value (Some name) true (V_Dict o)
end
