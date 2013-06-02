open Parsifal
open PTypes


struct png_file = {
  png_magic : magic("\x89\x50\x4e\x47\x0d\x0a\x1a\x0a");
  png_content : binstring;
}


let _ =
  try
    let input = string_input_of_filename Sys.argv.(1) in
    let png_file = parse_png_file input in
    print_endline (print_value (value_of_png_file png_file));
    exit 0
  with
    | ParsingException (e, h) -> prerr_endline (string_of_exception e h); exit 1
    | e -> prerr_endline (Printexc.to_string e); exit 1
