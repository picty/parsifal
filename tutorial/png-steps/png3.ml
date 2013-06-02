open Parsifal
open BasePTypes
open PTypes


struct png_chunk = {
  chunk_size : uint32;
  chunk_type : string(4);
  chunk_data : binstring(chunk_size);
  chunk_crc : uint32;
}

struct png_file = {
  png_magic : magic("\x89\x50\x4e\x47\x0d\x0a\x1a\x0a");
  chunks : list of png_chunk;
}


let is_chunk_critical c = ((int_of_char c.chunk_type.[0]) land 0x20) = 0

let clean_png_file png_file =
  let new_chunks = List.filter is_chunk_critical png_file.chunks in
  { png_file with chunks = new_chunks }


let display filename =
  let input = string_input_of_filename filename in
  let png_file = parse_png_file input in
  print_endline (print_value (value_of_png_file png_file))

let normalize src dst =
  let input = string_input_of_filename src in
  let png_file = parse_png_file input in
  let new_png_file = clean_png_file png_file in

  let output_file = open_out dst in
  let output = POutput.create () in
  dump_png_file output new_png_file;
  POutput.output_buffer output_file output


let _ =
  try
    match Array.length Sys.argv with
    | 2 -> display Sys.argv.(1); exit 0
    | 3 -> normalize Sys.argv.(1) Sys.argv.(2); exit 0
    | _ -> prerr_endline "Please provide one or two arguments."; exit 1
  with
    | ParsingException (e, h) -> prerr_endline (string_of_exception e h); exit 1
    | e -> prerr_endline (Printexc.to_string e); exit 1
