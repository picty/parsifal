open Parsifal
open BasePTypes
open PTypes

struct chunk = {
  chunk_size : uint32;
  chunk_type : string(4);
  chunk_data : binstring(chunk_size);
  chunk_crc : uint32;
}

struct png_file = {
  magic : magic("\x89PNG\r\n\x1a\n");
  chunks : list of chunk;
}

let print_chunk_type c =
  Printf.printf "%s: %d byte(s)\n" c.chunk_type c.chunk_size

let _ =
  if Array.length Sys.argv <> 2
  then failwith "Usage: ./pngtools <png file>";

  let input = string_input_of_filename Sys.argv.(1) in
  let png_file = parse_png_file input in
  List.iter print_chunk_type png_file.chunks

