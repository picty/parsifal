open Parsifal
open BasePTypes
open PTypes

open Guid
open Lzma

let align4 l =
  (lnot 3) land (l + 3)

let align8 l =
  (lnot 7) land (l + 7)

struct efi_fvb_attributes = {
  efi_fvb_read_disabled_cap : rtol_bit_bool;
  efi_fvb_read_enabled_cap : rtol_bit_bool;
  efi_fvb_read_status : rtol_bit_bool;

  efi_fvb_write_disabled_cap : rtol_bit_bool;
  efi_fvb_write_enabled_cap : rtol_bit_bool;
  efi_fvb_write_status : rtol_bit_bool;

  efi_fvb_lock_cap : rtol_bit_bool;
  efi_fvb_lock_status : rtol_bit_bool;

  parse_checkpoint _z1 : rtol_bit_bool;

  efi_fvb_sticky_write : rtol_bit_bool;
  efi_fvb_memory_mapped : rtol_bit_bool;
  efi_fvb_erase_polarity : rtol_bit_bool;

  parse_checkpoint _z2 : rtol_bit_int[3];

  efi_fvb_alignment : rtol_bit_int[17];
}

struct fv_block_map_entry = {
  num_blocks : uint32le;
  block_length : uint32le;

  parse_checkpoint : stop_if((num_blocks = 0) && (block_length = 0))
}

(* SECTION *)

enum section_type_t (8, UnknownVal UnknownSectionType) =
  | 0x00 -> Efi_Section_All
  (* Encapsulated section types *)
  | 0x01 -> Efi_Section_Compression
  | 0x02 -> Efi_Section_Guid_Defined
  (* Leaf section types *)
  | 0x10 -> Efi_Section_PE32
  | 0x11 -> Efi_Section_PIC
  | 0x12 -> Efi_Section_TE
  | 0x13 -> Efi_Section_DXE_Depex
  | 0x14 -> Efi_Section_Version
  | 0x15 -> Efi_Section_User_Interface
  | 0x16 -> Efi_Section_Compatibility16
  | 0x17 -> Efi_Section_Firmware_Volume_Image
  | 0x18 -> Efi_Section_Freeform_Subtype_Guid
  | 0x19 -> Efi_Section_Raw
  | 0x1b -> Efi_Section_Pei_Depex

enum efi_compression_type_t(8, UnknownVal UnknownEFICompressionType) =
  | 0x00 -> Efi_Not_Compressed
  | 0x01 -> Efi_Standard_Compression
  | 0x02 -> Efi_Customized_Compression

struct efi_section_common_header_t = {
  section_size : uint24le;
  section_type : section_type_t;
}

struct efi_section_header_compression_t = {
  uncompressed_length : uint32le;
  compression_type    : efi_compression_type_t;
}

struct efi_section_header_guid_defined_t = {
  section_definition_guid : guid;
  data_offset             : uint16le;
  attributes              : uint16le;
  (* XXX GuidSpecificHeaderFields *)
  guid_specific_header_fields : binstring(data_offset - 4 (* common header *) - 0x14 (* previous fields *));
}

union optional_section_header [enrich] (UnparsedOptSectionHeader of binstring(0)) =
  | Efi_Section_Compression -> Hdr_Section_Compressed of efi_section_header_compression_t
  | Efi_Section_Guid_Defined -> Hdr_Section_Guid_Defined of efi_section_header_guid_defined_t
  | Efi_Section_PE32 -> Hdr_Section_PE32
  | Efi_Section_Firmware_Volume_Image -> Hdr_Section_Firmware_Volume_Image
  | Efi_Section_Raw -> Hdr_Section_Raw

union section_contentWithParam [enrich] (UnparsedSectionContent) =
  | Efi_Section_Compression -> Section_Compressed of lzma_container of binstring
  | Efi_Section_PE32 -> Section_PE32 of binstring
  | Efi_Section_Firmware_Volume_Image -> Section_Firmware_Volume_Image of binstring

struct efi_file_section_header = {
  section_size : uint24le;
  section_type : section_type_t;
  section_rem  : optional_section_header (section_type);
}

(* end SECTION *)

(* EFI_FFS_FILE_HEADER *)
struct ffs_integrity_check = {
  header : uint8;
  file   : uint8;
}

enum efi_fv_filetype_t (8, UnknownVal EFI_FILETYPE_UNKNOWN) =
  | 0x00 -> EFI_FILETYPE_ALL
  | 0x01 -> EFI_FILETYPE_RAW
  | 0x02 -> EFI_FILETYPE_FREEFORM
  | 0x03 -> EFI_FILETYPE_SECURITY_CORE
  | 0x04 -> EFI_FILETYPE_PEI_CORE
  | 0x05 -> EFI_FILETYPE_DXE_CORE
  | 0x06 -> EFI_FILETYPE_PEIM
  | 0x07 -> EFI_FILETYPE_DRIVER
  | 0x08 -> EFI_FILETYPE_COMBINED_PEIM_DRIVER
  | 0x09 -> EFI_FILETYPE_APPLICATION
  | 0x0a -> EFI_FILETYPE_reserved_should_not_be_used
  | 0x0b -> EFI_FILETYPE_FIRMWARE_VOLUME_IMAGE
  | 0xf0 -> EFI_FILETYPE_PAD_FILE

struct ffs_file_header = {
  name : guid;                           (* 16 bytes *)
  integrity_check : ffs_integrity_check; (* 2 bytes  *)
  filetype : efi_fv_filetype_t;          (* 1 byte   *)
(*  attributes : uint8; *)
  attr2 : bit_int[1];
  attr_checksum : bit_int[1];
  attr_data_align : bit_int[3];
  attr_header_ext : bit_int[1];
  attr_recovery : bit_int[1];
  attr_tail_present : bit_int[1];

  size : uint24le;
  state : uint8;
}

struct ffs_file_tail = {
  tail : uint16le;
}

let parse_ffs_header_size hdr _ =
  let sizeof_hdr = 24 in (* size of FFS header *)
  let sizeof_tail = 2 * (hdr.attr_tail_present) in (* size of FFS tail *)
  (*
  Printf.printf "Hdr sz %d tail sz %d\n" sizeof_hdr sizeof_tail;
  Printf.printf "Hdr.sz %d (0x%x)\n" hdr.size hdr.size;
  *)
  (hdr.size - (sizeof_hdr + sizeof_tail))


let parse_end_marker zero input =
  if not (eos input) then begin
    let m = peek_string 16 input in
    if m = String.make 16 zero
    then drop_rem_bytes input
  end

type print_offset = unit
let parse_print_offset input = Printf.printf "Pouet %d\n" input.cur_offset

type debug_str_int
let parse_debug_int (s,i) input = Printf.printf "Pouet %s %d / cur: %d\n" s i input.cur_offset

struct ffs_section = {
  (* section headers are 4-bytes aligned with the parent's file image *)
  parse_checkpoint _align : binstring((align4 input.cur_offset) - input.cur_offset);
  (* if we reach EOS after aligning, this is not an error, just end of sections stream *)
  parse_checkpoint : stop_if( (eos input) );

  parse_checkpoint section_base : save_offset;
  section_hdr : efi_file_section_header;

  section_content : container(section_hdr.section_size - (input.cur_offset - section_base)) of section_contentWithParam(section_hdr.section_type);
}

union ffs_file_content [enrich; exhaustive] (UnparsedFileContent) =
  | EFI_FILETYPE_RAW -> RawFile of binstring
  | EFI_FILETYPE_PAD_FILE -> PadFile of binstring
  | _ -> FileSections of list of ffs_section

struct ffs_file [param zero] = {
  parse_checkpoint _align : binstring((align8 input.cur_offset) - input.cur_offset);

  header : ffs_file_header;
  parse_checkpoint content_size : ffs_header_size(header);

  sections : container(content_size) of ffs_file_content(header.filetype);

  (* XXX file tail, if header.attributes && FFS_ATTRIB_TAIL_PRESENT = 1 *)
  parse_checkpoint _end_marker : end_marker (zero);
}
(*  end EFI_FFS_FILE_HEADER *)

let zero_from_header attr =
  if attr.efi_fvb_erase_polarity then '\xff' else '\x00'

union fv_file_system [enrich; param fv_attr] (UnknownFVFileSystem) =
  | "EFI_FIRMWARE_FILE_SYSTEM_GUID" -> FFS of list of ffs_file(zero_from_header fv_attr)


let get_fs_length fv_length header_length =
  Int64.to_int (Int64.sub fv_length (Int64.of_int header_length))


struct fv_volume = {
  parse_checkpoint volume_base : save_offset;

  zero_vector : binstring(16);
  fs_guid : guid;
  fv_length : uint64le;

  (* offset : 0x28 *)
  signature : magic("_FVH");

  attributes : efi_fvb_attributes;
  header_length : uint16le;
  checksum : uint16le;
  reserved : binstring(3);
  revision : uint8;

  fv_block_map : list of fv_block_map_entry;
  junk2 : binstring(8);

  (* container begins after header_length *)
  fv_header_padding : binstring(header_length - (input.cur_offset - volume_base));

  file : container(get_fs_length fv_length header_length) of
                 fv_file_system (attributes; printable_name_of_guid fs_guid);


  (*junk : binstring *)
}

(* XXX carte de l'enfer de Boticelli XXX *)

