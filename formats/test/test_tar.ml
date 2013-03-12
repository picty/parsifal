open Lwt
open Parsifal
open Tar
open Getopt

type action = NoAction | Test | Create | Extract

let verbose = ref false
let archive = ref ""
let action = ref NoAction


let options = [
  mkopt (Some 'h') "help" Usage "show this help";
  mkopt (Some 'v') "verbose" (Set verbose) "talk more";

  mkopt (Some 't') "test" (TrivialFun (fun () -> action := Test)) "checks the archive";
  mkopt (Some 'c') "create" (TrivialFun (fun () -> action := Test)) "create an archive";
  mkopt (Some 'x') "extract" (TrivialFun (fun () -> action := Test)) "extract an archive";

  mkopt (Some 'f') "file" (StringVal archive) "name of the archive to consider"
]

let getopt_params = {
  default_progname = "test_tar";
  options = options;
  postprocess_funs = [];
}


let string_of_file_type = function
  | SymbolicLink -> 'l'
  | CharacterSpecial -> 'c'
  | BlockSpecial -> 'b'
  | Directory -> 'd'
  | FIFO -> 'p'
  | NormalFile
  | HardLink
  | ContiguousFile
  | UnknownFileType _ -> '-'

let string_of_right right =
  (if right land 4 <> 0 then "r" else "-") ^
  (if right land 2 <> 0 then "w" else "-") ^
  (if right land 1 <> 0 then "x" else "-")

let string_of_nts s =
  try
    let pos = String.index s '\x00' in
    String.sub s 0 pos
  with Not_found -> s

let string_of_user entry =
  match entry.ustar_header with
  | None -> string_of_int entry.owner_uid
  | Some h -> string_of_nts h.owner_user

let string_of_group entry =
  match entry.ustar_header with
  | None -> string_of_int entry.owner_gid
  | Some h -> string_of_nts h.owner_group


let print_entry entry =
  let header = entry.header in
  Printf.printf "%c%s%s%s %s/%s  %d %s\n"
    (string_of_file_type header.file_type)
    (string_of_right ((header.file_mode lsr 6) land 7))
    (string_of_right ((header.file_mode lsr 3) land 7))
    (string_of_right (header.file_mode land 7))
    (string_of_user header) (string_of_group header)
    header.file_size header.file_name


let check_archive filename =
  input_of_filename filename >>= lwt_parse_tar_file >>= fun tar_file ->
  if !verbose
  then List.iter print_entry tar_file;
  return ()


let _ =
  try
    let args = parse_args getopt_params Sys.argv in
    let t =
      if !archive == ""
      then fail (Failure "Please specify an archive name (--file)")
      else begin
	match !action, args with
	| Test, [] -> check_archive !archive
	| Test, _ -> fail (Failure "--test does not need arguments")
	| Create, _ -> fail (ParsingException (NotImplemented "--create", []))
	| Extract, _ -> fail (ParsingException (NotImplemented "--extract", []))
	| NoAction, _ -> fail (Failure "Please give an action (--test, --create or --extract)")
      end
    in
    Lwt_unix.run t;
    exit 0
  with
  | ParsingException (e, h) -> prerr_endline (string_of_exception e h); exit 1
  | e -> prerr_endline (Printexc.to_string e); exit 1

