open Lwt
open Parsifal
open Pe
open Getopt
open Unix
open PTypes

let options = [
  mkopt (Some 'h') "help" Usage "show this help";
]

let get_file_content filename =
  let f = open_in filename in
  let fd = descr_of_in_channel f in
  let stats = fstat fd in
  let len = stats.st_size in
  let res = String.make len ' ' in
  really_input f res 0 len;
  res

let parse_secdir_entry filename entry =
  let s = get_file_content filename in
  let input = input_of_string "SecDir Entry" s in
  parse_seek_offset entry.virtualaddress input;
  let win_crt = parse_win_certificate input in
  print_endline (print_value (value_of_win_certificate win_crt));
  return ()


(*
let parse_file filename =
  input_of_filename filename >>= lwt_parse_pe_file >>= fun pe_file ->
    print_endline (print_value (value_of_pe_file pe_file));
    return ()
*)
let parse_file filename =
  input_of_filename filename >>= lwt_parse_pe_file >>= fun pe_file ->
    print_endline (print_value (value_of_pe_file pe_file));
    let secdir_entry = pe_file.optpe_header.datadirectory.(4) in
    print_endline (print_value (value_of_data_directory_entry secdir_entry));
    return ()
    >>= fun _ ->
      print_endline "blah\n";
      let t = parse_secdir_entry filename secdir_entry in
      Lwt.join [t] >>= fun _ -> ();
    return ()


let main =
  try
    let args = parse_args ~progname:"test_pe" options Sys.argv in
    let t = match args with
      | [filename] -> parse_file filename
      | _ -> usage "test_pe" options (Some "Please provide exactly one filename.")
    in Lwt_unix.run t;
  with
  | ParsingException (e, h) -> prerr_endline (string_of_exception e h); exit 1
  | e -> prerr_endline (Printexc.to_string e); exit 1

let _ = main
