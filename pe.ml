open Parsifal
open BasePTypes
open PTypes


struct msdos_header [with_lwt] = {
  e_magic : magic["MZ"];
  e_cblp : uint16le;              (* Bytes on last page of file *)
  e_cp : uint16le;                (* Pages in file *)
  e_crlc : uint16le;              (* Relocations *)
  e_cparhdr : uint16le;           (* Size of header in paragraphs *)
  e_minalloc : uint16le;          (* Minimum extra paragraphs needed *)
  e_maxalloc : uint16le;          (* Maximum extra paragraphs needed *)
  e_ss : uint16le;                (* Initial (relative) SS value *)
  e_sp : uint16le;                (* Initial SP value *)
  e_csum : uint16le;              (* Checksum *)
  e_ip : uint16le;                (* Initial IP value *)
  e_cs : uint16le;                (* Initial (relative) CS value *)
  e_lfarlc : uint16le;            (* File address of relocation table *)
  e_ovno : uint16le;              (* Overlay number *)
  e_res : array(4) of uint16le;   (* Reserved words *)
  e_oemid : uint16le;             (* OEM identifier (for e_oeminfo) *)
  e_oeminfo : uint16le;           (* OEM information; e_oemid specific *)
  e_res2 : array(10) of uint16le; (* Reserved words *)
  e_lfanew : uint32le             (* File address of new exe header *)
}

enum subsystem [with_lwt; little_endian] (16, UnknownVal IMAGE_SUBSYSTEM_UNKNOWN) =
  | 1  -> IMAGE_SUBSYSTEM_NATIVE (* No subsystem required (device drivers and native system processes). *)
  | 2  -> IMAGE_SUBSYSTEM_WINDOWS_GUI (* Windows graphical user interface (GUI) subsystem. *)
	| 3  -> IMAGE_SUBSYSTEM_WINDOWS_CUI (* Windows character-mode user interface (CUI) subsystem. *)
	| 5  -> IMAGE_SUBSYSTEM_OS2_CUI (* OS/2 CUI subsystem. *)
	| 7  -> IMAGE_SUBSYSTEM_POSIX_CUI (* POSIX CUI subsystem. *)
	| 9  -> IMAGE_SUBSYSTEM_WINDOWS_CE_GUI (* Windows CE system. *)
	| 10 -> IMAGE_SUBSYSTEM_EFI_APPLICATION (* Extensible Firmware Interface (EFI) application. *)
	| 11 -> IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER (* EFI driver with boot services. *)
	| 12 -> IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER (* EFI driver with run-time services. *)
	| 13 -> IMAGE_SUBSYSTEM_EFI_ROM (* EFI ROM image. *)
	| 14 -> IMAGE_SUBSYSTEM_XBOX (* Xbox system. *)
	| 16 -> IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION (* Boot application. *)

struct pe_header [with_lwt] = {
  pe_magic : magic["PE\x00\x00"];
  machine : uint16le;      (* Machine type *)
  numsections : uint16le;  (* Number of Sections *)
  time : uint32le;         (* File Creation Time Stamp, number of seconds since epoch *)
  symboltable : uint32le;  (* File offset of the COFF symbol table *)
  numsymbols : uint32le;   (* Number of entries in the symbol table *)
  opthdsz : uint16le;      (* Size of the optional header, which is required for executable files but not for object files *)
  charact : uint16le       (* Flags that indicate the attributes of the file *)
}

enum optpe_magic [with_lwt; little_endian] (16, UnknownVal OPTPE_UNKNOWN) =
  | 0x10b  -> IMAGE_NT_OPTIONAL_HDR32_MAGIC
  | 0x107  -> IMAGE_ROM_OPTIONAL_HDR_MAGIC
  | 0x20b  -> IMAGE_NT_OPTIONAL_HDR64_MAGIC

struct optpe32_header [with_lwt] = {
  optpr_magic : optpe_magic;   (* Magic. 0x10b (normal exe), 0x107 (ROM image), 0x20b (PE32+) *)
  majorlinkerversion : uint8;
  minorlinkerversion : uint8;
  sizeofcode : uint32le;
  sizeofinitializeddata : uint32le;
  sizeofuninitializeddata : uint32le;
  addressofentrypoint : uint32le;
  baseofcode : uint32le;
  baseofdata : uint32le;
  imagebase : uint32le;
  sectionalignment : uint32le;
  filealignment : uint32le;
  majoroperatingsystemversion : uint16le;
  minoroperatingsystemversion : uint16le;
  majorimageversion : uint16le;
  minorimageversion : uint16le ;
  majorsubsystemversion : uint16le;
  minorsubsystemversion : uint16le;
  win32versionvalue : uint32le;
  sizeofimage : uint32le;
  sizeofheaders : uint32le;
  checksum : uint32le;
  subsystem : subsystem;
  dllcharacteristics : uint16le;
  sizeofstackreserve : uint32le;
  sizeofstackcommit : uint32le;
  sizeofheapreserve : uint32le;
  sizeofheapcommit : uint32le;
  loaderflags : uint32le;
  numberofrvaandsizes : uint32le
}

struct optpe64_header [with_lwt] = {
  optpr_magic : optpe_magic;   (* Magic. 0x10b (normal exe), 0x107 (ROM image), 0x20b (PE32+) *)
  majorlinkerversion : uint8;
  minorlinkerversion : uint8;
  sizeofcode : uint32le;
  sizeofinitializeddata : uint32le;
  sizeofuninitializeddata : uint32le;
  addressofentrypoint : uint32le;
  baseofcode : uint32le;
  imagebase : uint64le;
  sectionalignment : uint32le;
  filealignment : uint32le;
  majoroperatingsystemversion : uint16le;
  minoroperatingsystemversion : uint16le;
  majorimageversion : uint16le;
  minorimageversion : uint16le ;
  majorsubsystemversion : uint16le;
  minorsubsystemversion : uint16le;
  win32versionvalue : uint32le;
  sizeofimage : uint32le;
  sizeofheaders : uint32le;
  checksum : uint32le;
  subsystem : subsystem;
  dllcharacteristics : uint16le;
  sizeofstackreserve1 : uint64le;
  sizeofstackcommit : uint64le;
  sizeofheapreserve : uint64le;
  sizeofheapcommit : uint64le;
  loaderflags : uint32le;
  numberofrvaandsizes : uint32le
}

struct data_directory_entry [with_lwt] = {
  virtualaddress : uint32le;
  size : uint32le
}

struct pe_file [with_lwt] = {
  msdos_header: msdos_header;
  parse_checkpoint __e_dummyseek : seek_offset(0x3c);
  pehdr_loc : uint16le;
  parse_checkpoint __e_dummyseek2 : seek_offset(pehdr_loc);

  pe_header : pe_header;

  optpe_header : optpe64_header;

  datadirectory : array(16) of data_directory_entry
}
