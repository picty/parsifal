open Getopt

let verbose = ref false
let level = ref 0

let options = [
  mkopt (Some 'h') "help" Usage "show this help";
  mkopt (Some 'v') "verbose" (Set verbose) "activate the verbose mode";
  mkopt (Some 'l') "level" (IntVal level) "set the level";
]

let _ =
  let args = parse_args "test_getopt" options Sys.argv in
  Printf.printf "Verbose = %s\n" (string_of_bool !verbose);
  Printf.printf "Level = %d\n" !level;
  Printf.printf "Arguments =\n  %s\n" (String.concat "\n  " args)
