open Parsifal
open BasePTypes
open PTypes


union chunk_data [enrich] (UnparsedChunkData) =
  | "IHDR" -> ImageHeader of binstring
  | "PLTE" -> Palette of list of array(3) of uint8
  | "IDAT" -> ImageData of binstring
  | "IEND" -> ImageEnd


type crc_check = binstring

let parse_crc_check chunk_type chunk_data input =
  let crc = parse_string 4 input in
  let chunk_raw_data = exact_dump dump_chunk_data chunk_data in
  let computed_crc = Crc.crc32 (chunk_type ^ chunk_raw_data) in
  if computed_crc <> crc
  then Printf.printf "Invalid CRC: %s computed instead of %s\n" (hexdump computed_crc) (hexdump crc);
  computed_crc

let dump_crc_check = dump_binstring
let value_of_crc_check = value_of_binstring



struct chunk = {
  chunk_size : uint32;
  chunk_type : string(4);
  chunk_data : container(chunk_size) of chunk_data(chunk_type);
  chunk_crc : crc_check(chunk_type; chunk_data);
}

struct png_file = {
  magic : magic("\x89PNG\r\n\x1a\n");
  chunks : list of chunk;
}


let _ =
  if Array.length Sys.argv <> 2
  then failwith "Usage: ./pngtools <png file>";

  let input = string_input_of_filename Sys.argv.(1) in
  let png_file = parse_png_file input in
  print_endline (print_value (value_of_png_file png_file))
