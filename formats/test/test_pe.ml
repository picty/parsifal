open Lwt
open Parsifal
open Pe
open Getopt

let options = [
  mkopt (Some 'h') "help" Usage "show this help";
]

let getopt_params = {
  default_progname = "test_pe";
  options = options;
  postprocess_funs = [];
}

let parse_file filename =
  input_of_filename filename >>= lwt_parse_pe_file >>= fun pe_file ->
    print_endline (print_value (value_of_pe_file pe_file));
    return ()

let main =
  try
    let args = parse_args getopt_params Sys.argv in
    let t = match args with
      | [filename] -> parse_file filename
      | _ -> usage "test_pe" options (Some "Please provide exactly one filename.")
    in Lwt_unix.run t;
  with
  | ParsingException (e, h) -> prerr_endline (string_of_exception e h); exit 1
  | e -> prerr_endline (Printexc.to_string e); exit 1

let _ = main
