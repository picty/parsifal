enum mrt_type (16, UnknownVal MT_Unknown, [with_lwt]) =
  | 0 -> MT_NULL, "NULL"
  | 1 -> MT_START, "START"
  | 2 -> MT_DIE, "DIE"
  | 3 -> MT_I_AM_DEAD, "I_AM_DEAD"
  | 4 -> MT_PEER_DOWN, "PEER_DOWN"
  | 5 -> MT_BGP, "BGP"
  | 6 -> MT_RIP, "RIP"
  | 7 -> MT_IDRP, "IDRP"
  | 8 -> MT_RIPNG, "RIPNG"
  | 9 -> MT_BGP4PLUS, "BGP4PLUS"
  | 10 -> MT_BGP4PLUS_01, "BGP4PLUS_01"
  | 11 -> MT_OSPFv2, "OSPFv2"
  | 12 -> MT_TABLE_DUMP, "TABLE_DUMP"
  | 13 -> MT_TABLE_DUMP_V2, "TABLE_DUMP_V2"
  | 16 -> MT_BGP4MP, "BGP4MP"
  | 17 -> MT_BGP4MP_ET, "BGP4MP_ET"
  | 32 -> MT_ISIS, "ISIS"
  | 33 -> MT_ISIS_ET, "ISIS_ET"
  | 48 -> MT_OSPFv3, "OSPFv3"
  | 49 -> MT_OSPFv3_ET, "OSPFv3_ET"


enum ip_address_type (16, Exception InvalidIPAddressType, [with_lwt]) =
  | 1 -> AFI_IPv4, "AFI_IPv4"
  | 2 -> AFI_IPv6, "AFI_IPv6"

union ip_address (UnparsedIPAddress, [exhaustive; enrich]) =
  | AFI_IPv4 -> IPA_IPv4 of ipv4
  | AFI_IPv6 -> IPA_IPv6 of ipv6

union autonomous_system (UnparsedAS, [enrich]) =
  | 16 -> AS16 of uint16
  | 32 -> AS32 of uint32


enum table_dump_v2_subtype (16, UnknownVal Unknown_TableDumpV2SubType, [with_lwt]) =
  | 1 -> PEER_INDEX_TABLE, "PEER_INDEX_TABLE"
  | 2 -> RIB_IPV4_UNICAST, "RIB_IPV4_UNICAST"
  | 3 -> RIB_IPV4_MULTICAST, "RIB_IPV4_MULTICAST"
  | 4 -> RIB_IPV6_UNICAST, "RIB_IPV6_UNICAST"
  | 5 -> RIB_IPV6_MULTICAST, "RIB_IPV6_MULTICAST"
  | 6 -> RIB_GENERIC, "RIB_GENERIC"


enum peer_type (8, Exception InvalidPeerType, []) =
  | 0 -> PT_AS16_IPv4, "PT_AS16_IPv4"
  | 1 -> PT_AS16_IPv6, "PT_AS16_IPv6"
  | 2 -> PT_AS32_IPv4, "PT_AS32_IPv4"
  | 3 -> PT_AS32_IPv6, "PT_AS32_IPv6"

let as_size = function
  | PT_AS16_IPv4 | PT_AS16_IPv6 -> 16
  | PT_AS32_IPv4 | PT_AS32_IPv6 -> 32

let ip_address_type = function
  | PT_AS16_IPv4 | PT_AS32_IPv4 -> AFI_IPv4
  | PT_AS16_IPv6 | PT_AS32_IPv6 -> AFI_IPv6



struct peer_entry = {
  peer_type : peer_type;
  peer_bgp_id : uint32;
  peer_ip_address : ip_address(ip_address_type _peer_type);
  peer_as : autonomous_system(as_size _peer_type)
}


struct ospfv2_message = {
  remote_ip : ipv4;
  local_ip : ipv4;
  ospf_message_content : binstring
}

struct table_dump [param ipa_type] = {
  td_view_number : uint16;
  td_sequence_number : uint16;
  td_prefix : ip_address(ipa_type);
  td_prefix_length : uint8;
  td_status : uint8;
  td_originated_time : uint32;
  td_peer_ip_address : ip_address(ipa_type);
  td_peer_as : uint16;
  td_attribute : container(uint16) of binstring
}

struct peer_index_table = {
  collector_bgp_id : uint32;
  view_name : binstring(uint16);
  peer_count : uint16;
  peer_entries : list of peer_entry
}

struct rib_entry = {
  peer_index : uint16;
  rib_originated_time : uint32;
  rib_attribute : container(uint16) of binstring
}


type ip_prefix = IPv4Prefix of string * int | IPv6Prefix of string * int

let parse_ip_prefix ipa_type input =
  let prefix_length = ParsingEngine.parse_uint8 input in
  let l = (prefix_length + 7) / 8 in
  let s = ParsingEngine.parse_string l input in
  match ipa_type with
  | AFI_IPv4 -> IPv4Prefix (s, prefix_length)
  | AFI_IPv6 -> IPv6Prefix (s, prefix_length)

let dump_ip_prefix = function
  | IPv4Prefix (s, l)
  | IPv6Prefix (s, l) -> (DumpingEngine.dump_uint8 l) ^ s

let print_ip_prefix ident n ip_prefix =
  let a, len = match ip_prefix with
    | IPv4Prefix (s, prefix_length) ->
      let l = (prefix_length + 7) / 8 in
      PrintingEngine.string_of_ipv4 (s ^ (String.make (4 - l) '\x00')), prefix_length
    | IPv6Prefix (s, prefix_length) ->
      let l = (prefix_length + 7) / 8 in
      PrintingEngine.string_of_ipv6 (s ^ (String.make (16 - l) '\x00')), prefix_length
  in Printf.sprintf "%s%s: %s/%d\n" ident n a len


struct rib [param ipa_type] = {
  rib_sequence_number : uint32;
  rib_prefix : ip_prefix(ipa_type);
  rib_entry_count : uint16;
  rib_entries : list of rib_entry
}


union mrt_subtype (UnparsedSubType of uint16, [enrich; with_lwt]) =
  | MT_TABLE_DUMP -> MST_TABLE_DUMP of ip_address_type
  | MT_TABLE_DUMP_V2 -> MST_TABLE_DUMP_V2 of table_dump_v2_subtype

union mrt_message_content (UnparedMRTMessage, [enrich]) =
  | (MT_OSPFv2, _) -> OSPFv2Message of ospfv2_message
  | (MT_TABLE_DUMP, MST_TABLE_DUMP ipa_type) -> TableDump of table_dump(ipa_type)
  | (MT_TABLE_DUMP_V2, MST_TABLE_DUMP_V2 PEER_INDEX_TABLE) -> PeerIndexTable of peer_index_table
  | (MT_TABLE_DUMP_V2, MST_TABLE_DUMP_V2 RIB_IPV4_UNICAST) -> RIB of rib(AFI_IPv4)


let default_check_function typ subtyp input = ()
let parse_check_function = ref default_check_function

let default_lwt_check_function typ subtyp input = Lwt.return ()
let lwt_parse_check_function = ref default_lwt_check_function

struct mrt_message [top] = {
  mrt_timestamp : uint32;
  mrt_type : mrt_type;
  mrt_subtype : mrt_subtype(_mrt_type);
  mrt_checkpoint : checkref of check_function(_mrt_type; _mrt_subtype);
  mrt_message : container(uint32) of mrt_message_content(_mrt_type, _mrt_subtype)
}
