open Parsifal
open BasePTypes
open PTypes


enum file_type (8, UnknownVal UnknownFileType) =
  | 0 -> NormalFile
  | 0x30 -> NormalFile
  | 0x31 -> HardLink
  | 0x32 -> SymbolicLink
  | 0x33 -> CharacterSpecial
  | 0x34 -> BlockSpecial
  | 0x35 -> Directory
  | 0x36 -> FIFO
  | 0x37 -> ContiguousFile


type tar_numstring = int

let parse_tar_numstring len input =
  let octal_value = parse_string (len - 1) input in
  drop_bytes 1 input;
  try int_of_string ("0o" ^ octal_value)
  with _ -> raise (ParsingException (CustomException "int_of_string", _h_of_si input))

let dump_tar_numstring len buf v =
  POutput.bprintf buf "%*.*o\x00" len len v

let value_of_tar_numstring v = VSimpleInt v


union optional_tar_numstring [both_param len; enrich] (UnparsedNum of binstring(len)) =
  | CharacterSpecial -> Num of tar_numstring[len]
  | BlockSpecial -> Num of tar_numstring[len]


type azt_string = string

let parse_azt_string len input =
  let saved_offset = input.cur_offset in
  let s = parse_string len input in
  try
    let index = String.index s '\x00' in

    if String.sub s index (len - index) <> String.make (len - index) '\x00'
    then emit_parsing_exception false (CustomException "Unclean AZT String")
      { input with cur_offset = saved_offset };

    String.sub s 0 index;
  with Not_found -> s

let dump_azt_string len buf s =
  let missing_len = len - (String.length s) in
  POutput.add_string buf s;
  POutput.add_string buf (String.make missing_len '\x00')

let value_of_azt_string s = VString (s, false)


struct ustar_header [param file_type] =
{
  ustar_magic : magic("ustar");
  ustar_magic_padding : binstring(3);
  owner_user : azt_string[32];
  owner_group : azt_string[32];
  device_major : optional_tar_numstring[8](file_type);
  device_minor : optional_tar_numstring[8](file_type);
  filename_prefix : azt_string[155]
}

struct tar_header =
{
  file_name : azt_string[100];
  file_mode : tar_numstring[8];
  owner_uid : tar_numstring[8];
  owner_gid : tar_numstring[8];
  file_size : tar_numstring[12];
  timestamp : tar_numstring[12];
  checksum  : string(8);
  file_type : file_type;
  linked_file : azt_string[100];
  optional ustar_header : ustar_header(file_type);
  hdr_padding : binstring
}


struct tar_entry =
{
  header : container(512) of tar_header;
  file_content : binstring(header.file_size);
  file_padding : binstring(512 - (header.file_size mod 512))
}


let rec handle_entry input =
  let entry = parse_tar_entry input in
  print_endline (print_value (value_of_tar_header entry.header));
  handle_entry input

let _ =
  try
    let input = string_input_of_filename "test.tar" in
    handle_entry input
  with
  | ParsingException (e, h) -> prerr_endline (string_of_exception e h)
  | e -> prerr_endline (Printexc.to_string e)
