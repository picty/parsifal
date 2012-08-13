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



struct ospfv2_message = {
  remote_ip : ipv4;
  local_ip : ipv4;
  ospf_message_content : binstring
}

struct table_dump [param ipa_type] = {
  view_number : uint16;
  sequence_number : uint16;
  prefix : ip_address(ipa_type);
  originated_time : uint32;
  peer_ip_address : ip_address(ipa_type);
  peer_as : uint16;
  attribute : container(uint16) of binstring
}


union mrt_subtype (UnparsedSubType, [enrich; with_lwt]) =
  | MT_TABLE_DUMP -> MST_TABLE_DUMP of ip_address_type

union mrt_message_content (UnparedMRTMessage, [enrich]) =
  | (MT_OSPFv2, _) -> OSPFv2Message of ospfv2_message
  (* | (MT_TABLE_DUMP, MST_TABLE_DUMP ipa_type) -> TableDump of table_dump(ipa_type) *)
  | (MT_TABLE_DUMP, 1) -> TableDumpV4 of table_dump(AFI_IPv4)
  | (MT_TABLE_DUMP, 2) -> TableDumpV6 of table_dump(AFI_IPv6)


struct mrt_message [top] = {
  mrt_timestamp : uint32;
  mrt_type : mrt_type;
  mrt_subtype : (* mrt_subtype(_mrt_type) *) uint16;
  mrt_message : container(uint32) of mrt_message_content(_mrt_type, _mrt_subtype)
}
