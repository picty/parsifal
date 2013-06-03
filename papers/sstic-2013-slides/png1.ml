open Parsifal
open PTypes

struct png_file = {
  png_magic : magic("\x89\x50\x4e\x47\x0d\x0a\x1a\x0a");
  png_content : binstring;
}

let input = string_input_of_filename "test.png" in
let png = parse_png_file input in
print_endline (print_value (value_of_png_file png))
