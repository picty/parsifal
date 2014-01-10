open Parsifal
open Dvi


let extract_char buf = function
  | { command = DVIString (_, s) } -> Buffer.add_string buf s
  | { command = Right3 r } when r > 0x10000 -> Buffer.add_char buf ' '
  | { command = Down3 _ } -> Buffer.add_char buf '\n'
  | { command = EndOfPage } -> Buffer.add_string buf "\n\n"
  | _ -> ()


let rec simplify = function
  | [] -> []
  | { command = DVIString (_, "\x1b") }::r -> { opcode = OP_Opcode (-1); command = DVIString (-1, "ff") }::(simplify r)
  | { command = DVIString (_, "\x1c") }::r -> { opcode = OP_Opcode (-1); command = DVIString (-1, "fi") }::(simplify r)
  | { command = NoOperation }::r -> simplify r
  | { command = Right3 right }::r when right > 0x10000 ->
    { opcode = OP_Opcode (-1); command = DVIString (-1, " ") }::(simplify r)
  | { command = (W0|W1 _|W2 _|W3 _|W4 _|X0|X1 _|X2 _|X3 _|X4 _) }::r ->
    { opcode = OP_Opcode (-1); command = DVIString (-1, " ") }::(simplify r)
  | { command = Right3 _ }::r -> simplify r
  | x::r -> x::(simplify r)

let rec merge_chars = function
  | [] -> []
  | { command = DVIString (_, s1) }::{ command = DVIString (_, s2) }::r ->
    merge_chars ({ opcode = OP_Opcode (-1); command = DVIString (-1, s1 ^ s2) }::r)
  | x::r -> x::(merge_chars r)

let simplify_dvi l = merge_chars (simplify l)

let string_of_command_type = function
  | { command = DVIString _ } -> "string"
  | { opcode = o } -> string_of_opcode o

let print_dvi_command c =
  print_string (print_value ~name:(string_of_command_type c) (value_of_dvi_command_detail c.command))

let _ =
  let input = string_input_of_filename Sys.argv.(1) in
  let dvi = parse_dvi_file input in
  print_endline "= RAW DVI file =";
  List.iter print_dvi_command dvi;
(*  let buf = Buffer.create 1024 in
  List.iter (extract_char buf) dvi;
  print_endline (Buffer.contents buf);
  print_endline (print_value (value_of_dvi_file (simplify_dvi dvi))); *)
  print_endline "\n\n= \"Simplified\" DVI file =";
  List.iter print_dvi_command (simplify_dvi dvi)
  
