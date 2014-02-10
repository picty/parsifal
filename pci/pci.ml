open Parsifal
open BasePTypes
open PTypes

enum code_type_t (8, UnknownVal CODE_TYPE_UNKNOWN) =
  | 0x0  -> CODE_TYPE_X86 (* Intel x86, PC-AT compatible *)
  | 0x1  -> CODE_TYPE_OPENFIRMWARE (* Open Firmware standard for PCI *)
  | 0x2  -> CODE_TYPE_HPPE_RISC  (* Hewlett-Packard PA RISC *)
  | 0x3  -> CODE_TYPE_EFI (* Extensible Firmware Interface (EFI) *)

enum efi_subsystem_type_t [little_endian] (16, UnknownVal EFI_IMAGE_SUBSYSTEM_UNKNOWN) =
  | 0x000a  -> EFI_IMAGE_SUBSYSTEM_EFI_APPLICATION
  | 0x000b  -> EFI_IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER
  | 0x000c  -> EFI_IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER

enum efi_compression_type_t [little_endian] (16, UnknownVal EFI_COMPRESSION_TYPE_UNKNOWN) =
  | 0x0000  -> EFI_COMPRESSION_UNCOMPRESSED
  | 0x0001  -> EFI_COMPRESSION_COMPRESSED

enum efi_machine_type_t [little_endian] (16, UnknownVal EFI_MACHINE_TYPE_UNKNOWN) =
  | 0x014c  ->  EFI_IMAGE_MACHINE_IA32
  | 0x0200  ->  EFI_IMAGE_MACHINE_IA64
  | 0x0ebc  ->  EFI_IMAGE_MACHINE_EBC
  | 0x8664  ->  EFI_IMAGE_MACHINE_x64
  | 0x01c2  ->  EFI_IMAGE_MACHINE_ARMTHUMB_MIXED

struct option_rom_header = {
  signature : magic("\x55\xAA");
  reserved : binstring(0x16);
  pci_data_ptr : uint16le
}

struct option_rom_header_x86_64 = {
  signature : magic("\x55\xAA");
  image_size_legacy : uint8; (* current image size in units of 512 bytes *)
  entry_point_init : uint24; (* Entry point for INIT function. Power-On
  Self-Test (POST)does a FAR CALL to this location *) (* XXX little/big endian
  ?! *)
  reserved : binstring(0x12);
  pci_data_ptr_legacy : uint16le;
  exp_hdr_offset: uint16le
}

struct option_rom_header_efi = {
  signature : magic("\x55\xAA");
  image_size : uint16le; (* current image size in units of 512 bytes *)
  efi_signature: magic("\xf1\x0e");
  dummy0 : uint16le;
  subsystem : efi_subsystem_type_t;
  machine_type : efi_machine_type_t;
  compression_type : efi_compression_type_t;
  reserved : binstring(0x8);
  efi_image_ptr : uint16le;
  pci_data_ptr : uint16le
}

struct pci_data = {
  signature : magic("PCIR");
  vendor_id : uint16le;
  device_id : uint16le;
  device_list_ptr : uint16le; (* pointer to vital product data *)
  pci_data_struct_length : uint16le;
  pci_data_struct_revision : uint8;
  class_code : uint24le;
  image_length : uint16le;
  rom_vendor_revision : uint16le;
  code_type : code_type_t;
  last_image_indicator : uint8;
  reserved: uint16le
  (*
  max_runtime_image_length : uint16le;
  utility_code_hdr_ptr : uint16le;
  dmtf_clp_ptr : uint16le
  *)
}

struct rom_file_legacy = {
  parse_checkpoint pos1 : save_offset;
  option_rom_header_legacy: option_rom_header_x86_64;
  (* XXX error: this seek should be relative to the *start of the ROM* *)
  parse_checkpoint __e_dummyseek1 : seek_offset(pos1);
  (*parse_checkpoint __e_dummyseek_legacy :
    * seek_offsetrel(option_rom_header_legacy.pci_data_ptr_legacy);*)
  parse_checkpoint __e_dummyseek_legacy : seek_offset(pos1 + option_rom_header_legacy.pci_data_ptr_legacy);
  pci_data_legacy : pci_data
}

struct rom_file_efi = {
  parse_checkpoint pos1 : save_offset;
  option_rom_header: option_rom_header_efi;
  (* XXX error: this seek should be relative to the *start of the ROM* *)
  parse_checkpoint __e_dummyseek1 : seek_offset(pos1);
  (*parse_checkpoint __e_dummyseek :
    * seek_offsetrel(option_rom_header.pci_data_ptr);*)
  parse_checkpoint __e_dummyseek_legacy : seek_offset(pos1 + option_rom_header.pci_data_ptr);
  pci_data : pci_data
}

enum signature_type [little_endian] (16, UnknownVal Type_Legacy) =
  | 0x0ef1 -> Type_efi, "EfiRom"

union rom_content [enrich; exhaustive] (Unparsed_ROMContent)  =
  | Type_efi -> EfiRom of rom_file_efi
  | _ -> LegacyRom of rom_file_legacy

  (*
struct rom_image = {
  parse_checkpoint position_before_rom : save_offset;

  signature : magic["\x55\xAA"];

  __ignored1 : uint16le;
  test_signature: signature_type;

  (* go back to start of current rom *)
  parse_checkpoint __e_dummyseek : seek_offset(position_before_rom);

  rom_content : rom_content(test_signature)

  (* seek to end of image *)
  (*parse_checkpoint __e_dummyseek : last_entry(rom_content)*)

  (* TODO: test if lastimage indicator was set, if yes read again *)
}
*)


alias rom_image = rom_content

let parse_rom_image input =
  let pos = parse_save_offset input in
  drop_bytes 4 input;
  let signature_type = parse_signature_type input in
  (*print_endline (print_value (value_of_signature_type signature_type));*)
  parse_seek_offset pos input;
  parse_rom_content signature_type input

(*
let compute_next_rom_start rom =
  let size = match rom with
  | LegacyRom r -> r.option_rom_header_legacy.image_size_legacy
  | EfiRom r -> r.option_rom_header.image_size
  | Unparsed_ROMContent r s -> raise (ParsingException (CustomException ("unknown ROM type")))
  and base_offset = 0 (* rom.base_offset *) in (* parse_field = save_offset + un match
  *)
  base_offset + 512 * size
*)

(* TODO read the list of all images in one file *)
struct rom_file = {
  (*
  roms : array(1) of rom_image;
  parse_checkpoint __e_dummyseek : seek_offset(compute_next_rom_start roms.(0));
  *)
  rom2 : rom_image
(*
  rom1 : rom_file_legacy;
  parse_checkpoint __e_dummyseek : seek_offset(64000);
  rom2 : rom_file_efi
*)
}

