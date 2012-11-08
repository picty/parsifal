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


type tar_numstring = int

let parse_tar_numstring len input =
  let octal_value = parse_string (len - 1) input in
  drop_bytes 1 input;
  int_of_string ("0o" ^ octal_value)

let dump_tar_numstring len v =
  Printf.sprintf "%*.*o\x00" len len v

let print_tar_numstring ?indent:(indent="")
                        ?name:(name="numstring") v =
  Printf.sprintf "%s%s: %d (%o)\n" indent name v v


struct ustar_header = {
  ustar_magic : magic["ustar\x0000"];
  owner_user : string(32);
  owner_group : string(32);
  device_major : tar_numstring[8];
  device_minor : tar_numstring[8];
  filename_prefix : string(155)
}

let parse_last_entry name input =
  if name.[0] = '\x00'
  then raise ParsingStop

struct tar_header = {
  file_name : string(100);
  is_last_entry : check of last_entry (file_name);
  file_mode : tar_numstring[8];
  owner_uid : tar_numstring[8];
  owner_gid : tar_numstring[8];
  file_size : tar_numstring[12];
  timestamp : tar_numstring[12];
  checksum  : string(8);
  file_type : file_type;
  linked_file : string(100);
  optional ustar_header : ustar_header;
  hdr_padding : binstring
}

(* let check_crc32 _hdr _content _padding = () *)

struct tar_entry [with_lwt] = {
  header : container(512) of tar_header;
  file_content : binstring(header.file_size);
  file_padding : binstring(512 - (header.file_size mod 512))
  (* checksum_verification : check of check_crc32 (header, *)
  (*                                   file_content, file_padding); *)
}

alias tar_file [with_lwt] = list of tar_entry
