open Parsifal
open Pci


let _ =
  try
    let pci_filename =
      if Array.length Sys.argv > 1
      then Sys.argv.(1)
      else "test.pci"
    in
    let input = string_input_of_filename pci_filename in
    let pci_file = parse_rom_file input in
    print_endline (print_value (value_of_rom_file pci_file));
    exit 0
  with
  | ParsingException (e, h) -> prerr_endline (string_of_exception e h); exit 1
  | e -> prerr_endline (Printexc.to_string e); exit 1


