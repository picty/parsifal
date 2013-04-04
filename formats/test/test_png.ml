open Parsifal
open Png


let _ =
  try
    let png_filename =
      if Array.length Sys.argv > 1
      then Sys.argv.(1)
      else "test.png"
    in
    let input = string_input_of_filename png_filename in
    let png_file = parse_png_file input in
    print_endline (print_value (value_of_png_file png_file))
  with
  | ParsingException (e, h) -> prerr_endline (string_of_exception e h)
  | e -> prerr_endline (Printexc.to_string e)

 
