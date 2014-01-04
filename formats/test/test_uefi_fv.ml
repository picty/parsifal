open Parsifal
open Uefi_fv
open Getopt
open Guid

type action = NoAction | Test | Create | Extract

let verbose = ref false
let archive = ref ""
let outdir = ref ""
let action = ref NoAction


let options = [
  mkopt (Some 'h') "help" Usage "show this help";

  mkopt (Some 't') "test" (TrivialFun (fun () -> action := Test)) "checks the archive";
  mkopt (Some 'c') "create" (TrivialFun (fun () -> action := Create)) "create an archive";
  mkopt (Some 'x') "extract" (TrivialFun (fun () -> action := Extract)) "extract an archive";

  mkopt (Some 'f') "file" (StringVal archive) "name of the archive to consider";
  mkopt (Some 'o') "output" (StringVal outdir) "output directory";
  mkopt (Some 'v') "verbose" (Set verbose) "increase verbosity"
]

let type_of_value = function
  | VUnit -> "VUnit"
  | VBool _ -> "VBool"
  | VSimpleInt _ -> "VSimpleInt"
  | VInt (_, _, _) -> "Vint"
  | VBigInt (_, _) -> "VBigInt"
  | VString (_, false) -> "VString(_,false)"
  | VString (_, true) -> "VString(_,true)"
  | VEnum (_, _, _, _) -> "VEnum"
  | VList _ -> "VList"
  | VRecord _ -> "VRecord"
  | VOption None -> "VOption None"
  | VOption (Some _) -> "VOption(Some _)"
  | VError s -> "Error: " ^ s
  | VLazy _ -> "VLazy"
  | VUnparsed _ -> "VUnparsed"

let print_either g =
  match g with
  | Left err -> if !verbose then prerr_endline err
  | Right s -> let s2 = if String.length s > 80 then ((String.sub s 0 80) ^ "...") else s in
      print_endline s2

let get_value_from v path =
  let path_list = string_split '.' path in
  get_value path_list v

let raw_string_of_value v =
  match v with
  | VString(s,_) -> s
  | _ -> raise Not_found

let get_guid_of_value v =
  match v with
  | VRecord l -> begin
      try
        raw_string_of_value (List.assoc "@printable_name" l)
      with Not_found -> (string_of_value v)
  end
  | _ -> (string_of_value v)

let filename_cleanup s =
  let len = String.length s in
  let ret = String.make len '\x00' in
  let i = ref 0 in
  let j = ref 0 in
  while !i < len do
    begin
    let c = String.get s !i in
    let c2 =
      match c with
      | ' ' | '\012' | '\n' | '\r' | '\t' -> Some '.'
      | '/' -> Some '.'
      | '"' -> None
      | _ -> Some c
    in
    match c2 with
    | Some c -> ret.[!j] <- c; j := !j + 1; ()
    | None   -> ()
    end
    ;
    incr i
  done;
  String.sub ret 0 !j

(* Same as List.mapi
 * Reimplemented t work with ocaml < 4
 *
 * Apply function to all elements of list, calling f(index element)
 *
 * Build a list of all results and return it
 *)
let rec list_mapi i f = function
    [] -> []
  | a::l -> let r = f i a in r :: list_mapi (i + 1) f l

let list_mapi f l = list_mapi 0 f l

(* Same as List.iteri
 * Reimplemented t work with ocaml < 4
 *
 * Apply function to all elements of list, calling f(index element)
 *)
let rec list_iteri i f = function
    [] -> ()
  | a::l -> f i a; list_iteri (i + 1) f l

let list_iteri f l = list_iteri 0 f l


let string_to_file s filename =
  let oc = open_out_bin filename in
  output_string oc s;
  flush oc;
  close_out oc

let try_mkdir dirname =
  try
    Unix.mkdir dirname 0o755
  with
  | Unix.Unix_error(Unix.EEXIST,_,_) -> ()

let extract_string_to_file s =
  let filename = "/tmp/blah" in
  Printf.printf "writing to file %s length %d\n" filename (String.length s);
  string_to_file s filename

(* XXX FIXME print UTF-16 string *)
let ugly_print_utf16 s =
  String.iter (fun c ->
    if c <> '\x00' then print_char c else print_char '.'
  ) s;
  print_newline ()




let content_from_section section =
  let content = section.section_content in
  let section_type = string_of_section_type_t section.section_hdr.section_type in
  match content with
  | Section_Compressed s -> s
  | Section_PE32 s -> s
  | Section_Firmware_Volume_Image s -> s
  | UnparsedSectionContent s -> s
  | _ -> failwith ("Unhandled Section type " ^ section_type ^ " for content_from_section")


let rec extract_section_compressed current_dir section =
  let new_dir = current_dir ^ "/compressed" in
  try_mkdir new_dir;
  let raw_content = content_from_section section in
  let input_name = current_dir ^ "/compressed" in
  (* the decompressed image is then interpreted as a section stream *)
  try
    let input = input_of_string input_name raw_content in
    let dummy = BasePTypes.parse_rem_list "list" parse_ffs_section input in
    (* extract all sections *)
    list_iteri (fun i x ->
      Printf.printf "[%d] %s\n" i (print_value ~verbose:!verbose (value_of_ffs_section x));
      extract_section_from_file new_dir i x
    ) dummy
  with
  | ParsingException (e, h) -> flush_all ();
      prerr_endline "*** Warning: could not parse sections from compressed stream";
      prerr_endline (string_of_exception e h)


and extract_section_guid_defined current_dir section =
  let new_dir = current_dir ^ "/guid_defined" in
  try_mkdir new_dir;
  let raw_content = content_from_section section in
  let input_name = current_dir ^ "/guid_defined" in
  (* save the GUID *)
  let section_hdr_guid = match section.section_hdr.section_rem with
  | Hdr_Section_Guid_Defined h -> h.section_definition_guid
  | _ -> failwith "Header of Efi_Section_Guid_Defined is not Hdr_Section_Guid_Defined"
  in
  let guid_str = string_of_guid section_hdr_guid in
  string_to_file "" (new_dir ^ "/" ^ guid_str);
  (* the image is then interpreted as a section stream *)
  let input = input_of_string input_name raw_content in
  let dummy = BasePTypes.parse_rem_list "list" parse_ffs_section input in
  (* extract all sections *)
  list_iteri (fun i x ->
    Printf.printf "[%d] %s\n" i (print_value ~verbose:!verbose (value_of_ffs_section x));
    extract_section_from_file new_dir i x
  ) dummy
  (* XXX TODO if GUID is well known, iterate through section list, match sections of type
   * Efi_Section_Raw, and try to identify internal structures (like firmware volumes ...)
   *)


and extract_section_pe32 current_dir section =
  (* Nothing special to do *)
  ()


and extract_section_firmware_volume current_dir section =
  let new_dir = current_dir ^ "/firmware_volume" in
  try_mkdir new_dir;
  let raw_content = content_from_section section in
  let input_name = new_dir ^ "/firmware_volume" in
  (* parse the firmware volume image *)
  let input = input_of_string input_name raw_content in
  let fv = Uefi_fv.parse_fv_volume input in
  extract_firmware_volume new_dir fv


and extract_section_unparsed current_dir section =
  (* Nothing special to do *)
  ()


and extract_section_from_file current_dir idx section =
  let t = section.section_hdr.section_type in
  Printf.printf "\x1b[34mSection %.3d type: %d %s\x1b[30m\n" idx (int_of_section_type_t t) (string_of_section_type_t t);
  let new_dir = current_dir ^ "/section_" ^ (Printf.sprintf "%.3d" idx) in
  try_mkdir new_dir;
  (* save the section header *)
  let header_str = print_value ~verbose:!verbose (value_of_efi_file_section_header section.section_hdr) in
  string_to_file header_str (new_dir ^ "/header");
  (* XXX debug: save content to file *)
  let raw_content = content_from_section section in
  let input_name = new_dir ^ "/content" in
  string_to_file raw_content input_name;
  (* create an empty file, with section type as name *)
  let section_type = string_of_section_type_t section.section_hdr.section_type in
  string_to_file "" (new_dir ^ "/" ^ section_type);
  (* XXX debug *)
  Printf.printf "Section content type %s\n" (string_of_section_type_t t);
  match t with
  | Efi_Section_Compression -> extract_section_compressed new_dir section
  | Efi_Section_Guid_Defined -> extract_section_guid_defined new_dir section
  | Efi_Section_PE32 -> extract_section_pe32 new_dir section
  | Efi_Section_Firmware_Volume_Image -> extract_section_firmware_volume new_dir section
  | _ -> Printf.printf "*** Unhandled section type %s\n" (string_of_section_type_t t); extract_section_unparsed new_dir section


and extract_ffs_file current_dir idx file =
  Printf.printf "\x1b[31mextract_ffs_file %.3d\x1b[30m\n" idx;
  print_endline (string_of_guid file.header.name);
  print_endline (printable_name_of_guid file.header.name);
  (* work on sections *)
  (*print_either (get v "sections.*.section_hdr.section_type");*)
  let new_dir = current_dir ^ "/file_" ^ (Printf.sprintf "%.3d" idx) in
  try_mkdir new_dir;
  (* save the GUID *)
  let guid_str = string_of_guid file.header.name in
  string_to_file guid_str (new_dir ^ "/guid");
  (* create an empty file, with file type as name *)
  let file_type = string_of_efi_fv_filetype_t file.header.filetype in
  string_to_file "" (new_dir ^ "/" ^ file_type);
  (* save the file header *)
  let header_str = print_value ~verbose:!verbose (value_of_ffs_file_header file.header) in
  string_to_file header_str (new_dir ^ "/header");
  (* save all sections *)
  match file.sections with
  | FileSections l -> list_iteri (extract_section_from_file new_dir) l
  | RawFile f -> string_to_file f (new_dir ^ "/content")
  | _ -> Printf.printf "*** Unhandled sections for file type %s\n" (string_of_efi_fv_filetype_t file.header.filetype)




(* extract files recursively from value v, a Firmware File System (FFS) *)
and extract_ffs current_dir fv =
  print_endline "extract_ffs";
  (* iterate through all files *)
  match fv.file with
  | FFS files_l -> list_iteri (extract_ffs_file current_dir) files_l
  | UnknownFVFileSystem _ -> failwith "'file' attribute is not a list ?!"


and extract_firmware_volume current_dir fv =
  (* get the inner structure *)
  let guid_str = string_of_guid fv.fs_guid in
  let new_dir = current_dir ^ "/" ^ guid_str in
  try_mkdir new_dir;
  match printable_name_of_guid fv.fs_guid with
  | "EFI_FIRMWARE_FILE_SYSTEM_GUID" ->
      extract_ffs new_dir fv
  | _ -> failwith "Unknown FS GUID in firmware image"


(* extract firmware volume image *)
let extract_archive filename current_dir =
  if current_dir = "" then failwith "Missing output directory";
  let i = string_input_of_filename filename in
  print_string "[DEBUG] Extracting main file ...";
  let f = Uefi_fv.parse_fv_volume i in
  print_endline " done";
  try_mkdir current_dir;
  extract_firmware_volume current_dir f


let _ =
  try
    let args = parse_args ~progname:"test_tar" options Sys.argv in
    let _ =
      if !archive == ""
      then raise (Failure "Please specify an archive name (--file)")
      else begin
        match !action, args with
        | Test, [] -> raise (ParsingException (NotImplemented "--extract", []))
        | Test, _ -> raise (Failure "--test does not need arguments")
        | Create, _ -> raise (ParsingException (NotImplemented "--create", []))
        | Extract, _ -> extract_archive !archive !outdir
        | NoAction, _ -> raise (Failure "Please give an action (--test, --create or --extract)")
      end
    in
    ()
  with
  | ParsingException (e, h) -> flush_all (); prerr_endline (string_of_exception e h); exit 1
  | e -> prerr_endline (Printexc.to_string e); exit 1

