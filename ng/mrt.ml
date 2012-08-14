(* Generic useful types and functions *)

enum ip_address_type (16, Exception InvalidIPAddressType, [with_lwt]) =
  | 1 -> AFI_IPv4
  | 2 -> AFI_IPv6

union ip_address (UnparsedIPAddress, [exhaustive; enrich]) =
  | AFI_IPv4 -> IPA_IPv4 of ipv4
  | AFI_IPv6 -> IPA_IPv6 of ipv6

union autonomous_system (UnparsedAS, [enrich]) =
  | 16 -> AS16 of uint16
  | 32 -> AS32 of uint32

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




(* MRT Types *)

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


(* MT_OSPFv2 *)

struct ospfv2_message = {
  om_remote_ip : ipv4;
  om_local_ip : ipv4;
  om_ospf_message_content : binstring
}


(* MT_TABLE_DUMP *)

struct table_dump [param ipa_type] = {
  td_view_number : uint16;
  td_sequence_number : uint16;
  td_prefix : ip_address(ipa_type);
  td_prefix_length : uint8;
  td_status : uint8;
  td_originated_time : uint32;
  td_peer_ip_address : ip_address(ipa_type);
  td_peer_as : uint16;
  td_attribute : container[uint16] of binstring
}


(* MT_TABLE_DUMP_V2 *)

enum table_dump_v2_subtype (16, UnknownVal UnknownTableDumpV2SubType, [with_lwt]) =
  | 1 -> PEER_INDEX_TABLE
  | 2 -> RIB_IPV4_UNICAST
  | 3 -> RIB_IPV4_MULTICAST
  | 4 -> RIB_IPV6_UNICAST
  | 5 -> RIB_IPV6_MULTICAST
  | 6 -> RIB_GENERIC

enum peer_type (8, Exception InvalidPeerType, []) =
  | 0 -> PT_AS16_IPv4
  | 1 -> PT_AS16_IPv6
  | 2 -> PT_AS32_IPv4
  | 3 -> PT_AS32_IPv6

let as_size = function
  | PT_AS16_IPv4 | PT_AS16_IPv6 -> 16
  | PT_AS32_IPv4 | PT_AS32_IPv6 -> 32

let ip_address_type = function
  | PT_AS16_IPv4 | PT_AS32_IPv4 -> AFI_IPv4
  | PT_AS16_IPv6 | PT_AS32_IPv6 -> AFI_IPv6

struct peer_entry = {
  pe_peer_type : peer_type;
  pe_peer_bgp_id : uint32;
  pe_peer_ip_address : ip_address(ip_address_type _pe_peer_type);
  pe_peer_as : autonomous_system(as_size _pe_peer_type)
}


struct peer_index_table = {
  pit_collector_bgp_id : uint32;
  pit_view_name : binstring[uint16];
  pit_peer_count : uint16;
  pit_peer_entries : list of peer_entry
}

struct rib_entry = {
  rib_peer_index : uint16;
  rib_originated_time : uint32;
  rib_attribute : container[uint16] of binstring
}

struct rib [param ipa_type] = {
  rib_sequence_number : uint32;
  rib_prefix : ip_prefix(ipa_type);
  rib_entry_count : uint16;
  rib_entries : list of rib_entry
}

struct rib_generic = {
  rg_sequence_number : uint32;
  (* TODO: here we restrict ourselves to the only ipa we know: IPv4 and IPv6 *)
  address_family_identifier : ip_address_type;
  subsequent_afi : uint8;
  rg_nlri : ip_prefix(_address_family_identifier);
  rg_entry_count : uint16;
  rg_entries : list of rib_entry
}



(* MT_BGP4MP *)

enum bgp4mp_subtype (16, UnknownVal UnknownBGP4MPSubtype, [with_lwt]) =
  | 0 -> BGP4MP_STATE_CHANGE
  | 1 -> BGP4MP_MESSAGE
  | 4 -> BGP4MP_MESSAGE_AS4
  | 5 -> BGP4MP_STATE_CHANGE_AS4
  | 6 -> BGP4MP_MESSAGE_LOCAL
  | 7 -> BGP4MP_MESSAGE_AS4_LOCAL

type bgp_message_marker = unit
let parse_bgp_message_marker input =
  let s = ParsingEngine.parse_string 16 input in
  match s with
    | "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" -> ()
    | _ -> raise (Failure "Marker is not valid !")
let dump_bgp_message_marker () = String.make 16 '\xff'
let print_bgp_message_marker ident name () = PrintingEngine.print_binstring ident name ""


enum bgp_message_type (8, UnknownVal UnknownBGPMessageType, []) =
  | 1 -> BMT_OPEN
  | 2 -> BMT_UPDATE
  | 3 -> BMT_NOTIFICATION
  | 4 -> KEEPALIVE


struct bgp_open_message = {
  version : uint8;
  my_autonomous_system : autonomous_system(16);
  hold_time : uint16;
  bgp_identifier : uint32;
  optional_parameters : binstring[uint8] (* TODO *)
}

union bgp_message_content (UnparsedBGPMessageContent of binstring, [enrich]) =
  | BMT_OPEN -> BGP_Open of bgp_open_message
  | BMT_UPDATE -> BGP_Update of binstring (* TODO *)
  | BMT_NOTIFICATION -> BGP_Notification of binstring (* TODO *)
  | KEEPALIVE -> BGP_KeepAlive

struct bgp_message = {
  bgp_message_marker : bgp_message_marker;
  bgp_message_size : uint16;
  bgp_message_type : bgp_message_type;
  bgp_message_content : container(_bgp_message_size - 19) of bgp_message_content(_bgp_message_type)
}



struct bgp4mp_message [param is_as4] = {
  bm_peer_as_number : autonomous_system(if is_as4 then 32 else 16);
  bm_local_as_number : autonomous_system(if is_as4 then 32 else 16);
  bm_interface_index : uint16;
  bm_address_family : ip_address_type;
  bm_peer_ip_address : ip_address(_bm_address_family);
  bm_local_ip_address : ip_address(_bm_address_family);
  bm_bgp_message : bgp_message
}


union mrt_subtype (UnparsedSubType of uint16, [enrich; with_lwt]) =
  | MT_TABLE_DUMP -> MST_TABLE_DUMP of ip_address_type
  | MT_TABLE_DUMP_V2 -> MST_TABLE_DUMP_V2 of table_dump_v2_subtype
  | MT_BGP4MP -> MST_BGP4MP of bgp4mp_subtype


union mrt_message_content (UnparsedMRTMessage, [enrich]) =
  | (MT_OSPFv2, _) -> OSPFv2Message of ospfv2_message

  | (MT_TABLE_DUMP, MST_TABLE_DUMP ipa_type) -> TableDump of table_dump(ipa_type)

  | (MT_TABLE_DUMP_V2, MST_TABLE_DUMP_V2 PEER_INDEX_TABLE) -> PeerIndexTable of peer_index_table
  | (MT_TABLE_DUMP_V2, MST_TABLE_DUMP_V2 (RIB_IPV4_UNICAST|RIB_IPV4_MULTICAST)) -> RIB of rib(AFI_IPv4)
  | (MT_TABLE_DUMP_V2, MST_TABLE_DUMP_V2 (RIB_IPV6_UNICAST|RIB_IPV6_MULTICAST)) -> RIB of rib(AFI_IPv6)
  | (MT_TABLE_DUMP_V2, MST_TABLE_DUMP_V2 RIB_GENERIC) -> RIB_Generic of rib_generic

  | (MT_BGP4MP, MST_BGP4MP BGP4MP_MESSAGE) -> BGP4MP_Message of bgp4mp_message(false)
  | (MT_BGP4MP, MST_BGP4MP BGP4MP_MESSAGE_AS4) -> BGP4MP_Message of bgp4mp_message(true)


let default_check_function typ subtyp input = ()
let parse_check_function = ref default_check_function

let default_lwt_check_function typ subtyp input = Lwt.return ()
let lwt_parse_check_function = ref default_lwt_check_function

struct mrt_message [top] = {
  mrt_timestamp : uint32;
  mrt_type : mrt_type;
  mrt_subtype : mrt_subtype(_mrt_type);
  mrt_checkpoint : checkref of check_function(_mrt_type; _mrt_subtype);
  mrt_message : container[uint32] of mrt_message_content(_mrt_type, _mrt_subtype)
}
