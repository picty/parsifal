open Parsifal
open BasePTypes
open PTypes

type guid = {
  data1: uint32le;
  data2: uint16le;
  data3: uint16le;
  data4: uint64;
}

struct guid_registry_item = {
  n: string;
  g: list of uint32;
}

let guid_registry = [
  {n="EFI_FIRMWARE_FILE_SYSTEM_GUID"; g=[0x7A9354D9; 0x0468; 0x444a; 0x81; 0xCE; 0x0B; 0xF6; 0x17; 0xD8; 0x90; 0xdf]};
  (*
   * NEST MODULES
   * ----------------------------------------------------------------------
   * Modules that have another modules inside, packed or not
   *)
  {n="Phoenix/Insyde nest"; g=[0x4a538818; 0x5ae0; 0x4eb2; 0xb2; 0xeb; 0x48; 0x8b; 0x23; 0x65; 0x70; 0x22]};
  {n="AMI nest"; g=[0xAE717C2F; 0x1A42; 0x4F2B; 0x88; 0x61; 0x78; 0xb7; 0x9c; 0xa0; 0x7e; 0x07]};
  (*
   * Firmare encoding
   * ----------------------------------------------------------------------
   * Extracted from http://feishare.com/edk2doxygen/dc/d54/class_eot_1_1_fv_image_1_1_guid_defined_image.html
   *)
  {n="CRC32_GUID"; g=[0xFC1BCDB0; 0x7D31; 0x49AA; 0x93; 0x6A; 0xA4; 0x60; 0x0D; 0x9D; 0xD0; 0x83]};
  {n="LZMA_COMPRESS_GUID"; g=[0xEE4E5898; 0x3914; 0x4259; 0x9D; 0x6E; 0xDC; 0x7B; 0xD7; 0x94; 0x03; 0xCF]};
  {n="TIANO_COMPRESS_GUID"; g=[0xA31280AD; 0x481E; 0x41B6; 0x95; 0xE8; 0x12; 0x7F; 0x4C; 0x98; 0x47; 0x79]};
  (*
   * Misc MODULES
   * ----------------------------------------------------------------------
   * Misc Modules
   *)
  {n="AMITSE"; g=[0xB1DA0ADF; 0x4f77; 0x4070; 0xa8; 0x8e; 0xbf; 0xfe; 0x1c; 0x60; 0x52; 0x9a]};
  {n="AMI NVRAM"; g=[0xCEF5B9A3; 0x476D; 0x497F; 0x9f; 0xdc; 0xe9; 0x81; 0x43; 0xe0; 0x42; 0x2c]};
  (*
   * Found MODULES
   * ----------------------------------------------------------------------
   * Misc Modules found in real images
   *)
  {n="FFS_FILEGUID_DXE_Core"; g=[0x35B898CA; 0xB6A9; 0x49CE; 0x8C; 0x72; 0x90; 0x47; 0x35; 0xCC; 0x49; 0xB7]};
]

let match_guid candidate reference =
  match reference.g with
  | g1::g2::g3::rem ->
      if candidate.data1 = g1 &&
       candidate.data2 = g2 &&
       candidate.data3 = g3
      then begin
        let shift_and_add a b =
          Int64.add (Int64.shift_left a 8) (Int64.of_int b)
        in
        let value = List.fold_left shift_and_add 0L rem in
        if Int64.compare value candidate.data4 = 0 then
          true
        else
          false
      end
      else
        false
  | _ -> false

let find_guid g =
  List.find (match_guid g) guid_registry

let guid_of_name name =
  List.find (fun r -> r.n = name) guid_registry

let printable_name_of_guid g =
  try
    let item = find_guid g in
    item.n
  with Not_found -> "Unknown GUID"

let parse_guid input =
  let d1 = parse_uint32le input in
  let d2 = parse_uint16le input in
  let d3 = parse_uint16le input in
  let d4 = parse_uint64 input in
  { data1=d1; data2=d2; data3=d3; data4=d4 }

let string_of_guid g =
  let d4a = Int64.shift_right_logical g.data4 48 in
  let d4b = Int64.logand g.data4 (0xffffffffffffL) in
  Printf.sprintf "%.8x-%.4x-%.4x-%.4Lx-%.12Lx" g.data1 g.data2 g.data3 d4a d4b

let value_of_guid g =
  let content = string_of_guid g in
  let name = printable_name_of_guid g in
  VRecord [
    "@name", VString("GUID", false);
    "@string_of", VString(content, false);
    "@printable_name", VString(name, false);
  ]

let dump_guid buf g =
  POutput.bprintf buf "%s" (string_of_guid g)


