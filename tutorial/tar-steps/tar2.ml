open Parsifal
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

struct ustar_header =
{
  ustar_magic : magic("ustar");
  ustar_magic_padding : binstring(3);
  owner_user : string(32);
  owner_group : string(32);
  device_major : string(8);
  device_minor : string(8);
  filename_prefix : string(155)
}

struct tar_header =
{
  file_name : string(100);
  file_mode : string(8);
  owner_uid : string(8);
  owner_gid : string(8);
  file_size : string(12);
  timestamp : string(12);
  checksum  : string(8);
  file_type : file_type;
  linked_file : string(100);
  optional ustar_header : ustar_header;
  hdr_padding : binstring
}

let int_of_tarstring octal_value =
  let len = String.length octal_value in
  if len = 0
  then 0
  else begin
    let real_octal_value = String.sub octal_value 0 (len -1) in
    int_of_string ("0o" ^ real_octal_value)
  end


struct tar_entry =
{
  header : container(512) of tar_header;
  file_content : binstring(int_of_tarstring header.file_size);
  file_padding : binstring(512 - ((int_of_tarstring header.file_size) mod 512))
}


let rec handle_entry input =
  let entry = parse_tar_entry input in
  print_endline (print_value (value_of_tar_header entry.header));
  handle_entry input

let _ =
  let input = string_input_of_filename "test.tar" in
  handle_entry input
