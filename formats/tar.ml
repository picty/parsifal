open Parsifal
open BasePTypes
open PTypes

(* TODO: Mark ustar as one possible extra header *)

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
  Printf.bprintf buf "%*.*o\x00" len len v

(* TODO: change stg to get len in here? *)
let value_of_tar_numstring i = VSimpleInt i


union optional_tar_numstring [both_param len; enrich] (UnparsedNum of binstring(len)) =
  | CharacterSpecial -> Num of tar_numstring(BOTH len)
  | BlockSpecial -> Num of tar_numstring(BOTH len)


struct ustar_header [param file_type] = {
  ustar_magic : magic("ustar");
  _ustar_magic_padding : binstring(3);
  owner_user : nt_string(BOTH 32);
  owner_group : nt_string(BOTH 32);
  device_major : optional_tar_numstring(BOTH 8; file_type);
  device_minor : optional_tar_numstring(BOTH 8; file_type);
  filename_prefix : nt_string(BOTH 155)
}

struct tar_header = {
  file_name : nt_string(BOTH 100);
  parse_checkpoint _last_entry : stop_if(file_name = "");
  file_mode : tar_numstring(BOTH 8);
  owner_uid : tar_numstring(BOTH 8);
  owner_gid : tar_numstring(BOTH 8);
  file_size : tar_numstring(BOTH 12);
  timestamp : tar_numstring(BOTH 12);
  checksum  : string(8);
  file_type : file_type;
  linked_file : nt_string(BOTH 100);
  optional ustar_header : ustar_header(file_type);
  _hdr_padding : binstring
}


(* let check_crc32 _hdr _content _padding = () *)

let padding_size file_size =
  (512 - (file_size mod 512)) mod 512

struct tar_entry [with_lwt] = {
  header : container(512) of tar_header;
  file_content : binstring(header.file_size);
  file_padding : binstring(padding_size header.file_size)
  (* checksum_verification : check of check_crc32 (header, *)
  (*                                   file_content, file_padding); *)
}

alias tar_file [with_lwt] = list of tar_entry
