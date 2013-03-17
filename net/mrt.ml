open Parsifal
open BasePTypes
open PTypes


(* Generic useful types and functions *)

enum address_family_identifier [with_lwt] (16, Exception InvalidAddressFamilyIdentifier) =
  | 1 -> AFI_IPv4
  | 2 -> AFI_IPv6

enum subsequent_address_family_identifier (8, Exception InvalidSubsequentAddressFamilyIdentifier) =
  | 1 -> SAFI_Unicast
  | 2 -> SAFI_Multicast

union ip_address [exhaustive; enrich] (UnparsedIPAddress) =
  | AFI_IPv4 -> IPA_IPv4 of ipv4
  | AFI_IPv6 -> IPA_IPv6 of ipv6

union autonomous_system [enrich] (UnparsedAS) =
  | 16 -> AS16 of uint16
  | 32 -> AS32 of uint32

type ip_prefix = IPv4Prefix of string * int | IPv6Prefix of string * int

let parse_ip_prefix ipa_type input =
  let prefix_length = parse_uint8 input in
  let l = (prefix_length + 7) / 8 in
  let s = parse_string l input in
  match ipa_type with
  | AFI_IPv4 -> IPv4Prefix (s, prefix_length)
  | AFI_IPv6 -> IPv6Prefix (s, prefix_length)

let dump_ip_prefix = function
  | IPv4Prefix (s, l)
  | IPv6Prefix (s, l) -> (dump_uint8 l) ^ s

let string_of_ip_prefix ip_prefix =
  let a, len = match ip_prefix with
    | IPv4Prefix (s, prefix_length) ->
      let l = (prefix_length + 7) / 8 in
      string_of_ipv4 (s ^ (String.make (4 - l) '\x00')), prefix_length
    | IPv6Prefix (s, prefix_length) ->
      let l = (prefix_length + 7) / 8 in
      string_of_ipv6 (s ^ (String.make (16 - l) '\x00')), prefix_length
  in Printf.sprintf "%s/%d" a len

let get_ip_prefix = trivial_get dump_ip_prefix string_of_ip_prefix

let value_of_ip_prefix = function
  | IPv4Prefix (initial_s, prefix_len) ->
    let l = (prefix_len + 7) / 8 in
    let s = initial_s ^ (String.make (4 - l) '\x00') in
    let elts = [s.[0]; s.[1]; s.[2]; s.[3]] in
    VRecord [
      "@name", VString ("ipv4_prefix", false);
      "@string_of", VString ((string_of_ipv4 s) ^ "/" ^ (string_of_int prefix_len), false);
      "prefix", VList (List.map (fun x -> VSimpleInt (int_of_char x)) elts);
      "prefix_len", VSimpleInt prefix_len
    ]
  | IPv6Prefix (initial_s, prefix_len) ->
    let l = (prefix_len + 7) / 8 in
    let s = initial_s ^ (String.make (16 - l) '\x00') in
    let elts = [s.[0]; s.[1]; s.[2]; s.[3];
		s.[4]; s.[5]; s.[6]; s.[7];
		s.[8]; s.[9]; s.[10]; s.[11];
		s.[12]; s.[13]; s.[14]; s.[15]] in
    VRecord [
      "@name", VString ("ipv6_prefix", false);
      "@string_of", VString ((string_of_ipv6 s) ^ "/" ^ (string_of_int prefix_len), false);
      "prefix", VList (List.map (fun x -> VSimpleInt (int_of_char x)) elts);
      "prefix_len", VSimpleInt prefix_len
    ]



(* BGP messages *)

struct bgp_open_message = {
  version : uint8;
  my_autonomous_system : autonomous_system(16);
  hold_time : uint16;
  bgp_identifier : uint32;
  optional_parameters__unparsed : binstring[uint8] (* TODO *)
}

type bgp_attribute_len = bool * int
let parse_bgp_attribute_len attr input =
  if (attr land 0x10) = 0x10
  then true, parse_uint16 input
  else false, parse_uint8 input
let dump_bgp_attribute_len (extended, v) =
  if extended
  then dump_uint16 v
  else dump_uint8 v
let string_of_bgp_attribute_len (_, v) = string_of_int v
let get_bgp_attribute_len = trivial_get dump_bgp_attribute_len string_of_bgp_attribute_len
let value_of_bgp_attribute_len (extended, v) =
  if extended
  then VInt (v, 16, BigEndian)
  else VInt (v, 8, BigEndian)

enum bgp_attribute_type (8, UnknownVal UnknownBGPAttributeType) =
  | 1 -> ORIGIN
  | 2 -> AS_PATH
  | 3 -> NEXT_HOP
  | 4 -> MULTI_EXIT_DISC
  | 5 -> LOCAL_PREF
  | 6 -> ATOMIC_AGGREGATE
  | 7 -> AGGREGATOR
  | 8 -> COMMUNITY
  | 14 -> MP_REACH_NLRI
  | 15 -> MP_UNREACH_NLRI
  | 16 -> EXTENDED_COMMUNITIES
  | 17 -> AS4_PATH
  | 18 -> AS4_AGGREGATOR

enum bgp_origin (8, UnknownVal UnknownBGPOrigin) =
  | 0 -> IGP
  | 1 -> EGP
  | 2 -> INCOMPLETE

enum path_segment_type (8, UnknownVal UnknownBGPASPath) =
  | 1 -> AS_SET
  | 2 -> AS_SEQUENCE

struct bgp_as_path_segment [param as_size] = {
  path_segment_type : path_segment_type;
  path_segment_length : uint8;
  path_segment_value : list(path_segment_length) of autonomous_system(as_size)
}

struct bgp_aggregator [param as_size] = {
  agg_as : autonomous_system(as_size);
  agg_ip : ipv4
}


struct bgp_reach_nlri_full = {
  rn_afi : address_family_identifier;
  rn_safi : subsequent_address_family_identifier;
  rn_next_hop : container[uint8] of list of (ip_address(rn_afi));
  rn_reserved : uint8;
  rn_nlri : list of ip_prefix(rn_afi)
}  

union bgp_reach_nlri (AbbreviatedNLRI of container[uint8] of list of (ip_address(AFI_IPv6))) =
  | 1 -> FullNLRI of bgp_reach_nlri_full
  | 2 -> FullNLRI of bgp_reach_nlri_full

struct bgp_unreach_nlri = {
  un_afi : address_family_identifier;
  un_safi : subsequent_address_family_identifier;
  un_withdrawn_routes : list of ip_prefix(un_afi)
}  

union bgp_attribute_content [enrich; param as_size] (UnknownBGPAttributeContent) =
  | ORIGIN -> BAC_Origin of bgp_origin
  | AS_PATH -> BAC_ASPath of (list of bgp_as_path_segment(as_size))
  | NEXT_HOP -> BAC_NextHop of ipv4
  | MULTI_EXIT_DISC -> BAC_MultiExitDisc of uint32
  | ATOMIC_AGGREGATE -> BAC_AtomicAggregate
  | AGGREGATOR -> BAC_Aggregator of bgp_aggregator(as_size)
  | COMMUNITY -> BAC_Community of (list of uint32)
  | MP_REACH_NLRI -> BAC_MPReachNLRI of bgp_reach_nlri(peek_uint16 input)
  | MP_UNREACH_NLRI -> BAC_MPUnreachNLRI of bgp_unreach_nlri
  | EXTENDED_COMMUNITIES -> BAC_ExtendedCommunities of (list of binstring(8)) (* TODO rfc4360 *)
  | AS4_PATH -> BAC_ASPath of (list of bgp_as_path_segment(32))
  | AS4_AGGREGATOR -> BAC_AS4Aggregator of bgp_aggregator(32)
(* Some attribute are still missing (see http://www.iana.org/assignments/bgp-parameters/bgp-parameters.xml *)


struct bgp_attribute [param as_size] = {
  attr_flags : uint8;
  attr_type : bgp_attribute_type;
  attr_len : bgp_attribute_len(attr_flags);
  attr_content : container(snd attr_len) of bgp_attribute_content(as_size; attr_type)
}

struct bgp_update_message [param ipa_type; param as_size] = {
  withdrawn_routes : container[uint16] of (list of ip_prefix(ipa_type));
  path_attributes : container[uint16] of (list of bgp_attribute(as_size));
  network_layer_reachability_information : list of (ip_prefix(ipa_type))
}

struct bgp_route_refresh = {
  rr_afi : address_family_identifier;
  rr_reserved : uint8;
  rr_safi : subsequent_address_family_identifier
}


enum bgp_message_type (8, UnknownVal UnknownBGPMessageType) =
  | 1 -> BMT_OPEN
  | 2 -> BMT_UPDATE
  | 3 -> BMT_NOTIFICATION
  | 4 -> BMT_KEEPALIVE
  | 5 -> BMT_ROUTE_REFRESH

union bgp_message_content [enrich; param ipa_type; param as_size] (UnparsedBGPMessageContent of binstring) =
  | BMT_OPEN -> BGP_Open of bgp_open_message
  | BMT_UPDATE -> BGP_Update of bgp_update_message(ipa_type; as_size)
  | BMT_NOTIFICATION -> BGP_Notification of binstring (* TODO *)
  | BMT_KEEPALIVE -> BGP_KeepAlive
  | BMT_ROUTE_REFRESH -> BGP_RouteRefresh of bgp_route_refresh

alias bgp_message_marker = magic ("\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff")

struct bgp_message [param ipa_type; param as_size] = {
  bgp_message_marker : bgp_message_marker;
  bgp_message_size : uint16;
  bgp_message_type : bgp_message_type;
  bgp_message_content : container(bgp_message_size - 19) of bgp_message_content(ipa_type; as_size; bgp_message_type)
}



(* MRT Types *)

enum mrt_type [with_lwt] (16, UnknownVal MT_Unknown) =
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
  om_ospf_message_content : binstring (* TODO *)
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
  td_attribute : container[uint16] of (list of bgp_attribute(16))
}


(* MT_TABLE_DUMP_V2 *)

enum table_dump_v2_subtype [with_lwt] (16, UnknownVal UnknownTableDumpV2SubType) =
  | 1 -> PEER_INDEX_TABLE
  | 2 -> RIB_IPV4_UNICAST
  | 3 -> RIB_IPV4_MULTICAST
  | 4 -> RIB_IPV6_UNICAST
  | 5 -> RIB_IPV6_MULTICAST
  | 6 -> RIB_GENERIC

enum peer_type (8, Exception InvalidPeerType) =
  | 0 -> PT_AS16_IPv4
  | 1 -> PT_AS16_IPv6
  | 2 -> PT_AS32_IPv4
  | 3 -> PT_AS32_IPv6

let as_size = function
  | PT_AS16_IPv4 | PT_AS16_IPv6 -> 16
  | PT_AS32_IPv4 | PT_AS32_IPv6 -> 32

let afi = function
  | PT_AS16_IPv4 | PT_AS32_IPv4 -> AFI_IPv4
  | PT_AS16_IPv6 | PT_AS32_IPv6 -> AFI_IPv6

struct peer_entry = {
  pe_peer_type : peer_type;
  pe_peer_bgp_id : uint32;
  pe_peer_ip_address : ip_address(afi pe_peer_type);
  pe_peer_as : autonomous_system(as_size pe_peer_type)
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
  rib_attribute : container[uint16] of (list of bgp_attribute(32))
}

struct rib [param ipa_type] = {
  rib_sequence_number : uint32;
  rib_prefix : ip_prefix(ipa_type);
  rib_entry_count : uint16;
  rib_entries : list of rib_entry
}

struct rib_generic = {
  rg_sequence_number : uint32;
  rg_afi : address_family_identifier;
  rg_safi : subsequent_address_family_identifier;
  rg_nlri : ip_prefix(rg_afi);
  rg_entry_count : uint16;
  rg_entries : list of rib_entry
}



(* MT_BGP4MP *)

enum bgp4mp_subtype [with_lwt] (16, UnknownVal UnknownBGP4MPSubtype) =
  | 0 -> BGP4MP_STATE_CHANGE
  | 1 -> BGP4MP_MESSAGE
  | 4 -> BGP4MP_MESSAGE_AS4
  | 5 -> BGP4MP_STATE_CHANGE_AS4
  | 6 -> BGP4MP_MESSAGE_LOCAL
  | 7 -> BGP4MP_MESSAGE_AS4_LOCAL

struct bgp4mp_message [param is_as4] = {
  bm_peer_as_number : autonomous_system(if is_as4 then 32 else 16);
  bm_local_as_number : autonomous_system(if is_as4 then 32 else 16);
  bm_interface_index : uint16;
  bm_afi : address_family_identifier;
  bm_peer_ip_address : ip_address(bm_afi);
  bm_local_ip_address : ip_address(bm_afi);
  bm_bgp_message : bgp_message(bm_afi; if is_as4 then 32 else 16)
}


union mrt_subtype [enrich; with_lwt] (UnparsedSubType of uint16) =
  | MT_TABLE_DUMP -> MST_TABLE_DUMP of address_family_identifier
  | MT_TABLE_DUMP_V2 -> MST_TABLE_DUMP_V2 of table_dump_v2_subtype
  | MT_BGP4MP -> MST_BGP4MP of bgp4mp_subtype


(* TODO: Some types/subtypes are not parsed deeply for the moment *)
union mrt_message_content [enrich] (UnparsedMRTMessage) =
  | (MT_OSPFv2, _) -> OSPFv2Message of ospfv2_message

  | (MT_TABLE_DUMP, MST_TABLE_DUMP ipa_type) -> TableDump of table_dump(ipa_type)

  | (MT_TABLE_DUMP_V2, MST_TABLE_DUMP_V2 PEER_INDEX_TABLE) -> PeerIndexTable of peer_index_table
  | (MT_TABLE_DUMP_V2, MST_TABLE_DUMP_V2 (RIB_IPV4_UNICAST|RIB_IPV4_MULTICAST)) -> RIB of rib(AFI_IPv4)
  | (MT_TABLE_DUMP_V2, MST_TABLE_DUMP_V2 (RIB_IPV6_UNICAST|RIB_IPV6_MULTICAST)) -> RIB of rib(AFI_IPv6)
  | (MT_TABLE_DUMP_V2, MST_TABLE_DUMP_V2 RIB_GENERIC) -> RIB_Generic of rib_generic

  | (MT_BGP4MP, MST_BGP4MP BGP4MP_MESSAGE) -> BGP4MP_Message of bgp4mp_message(false)
  | (MT_BGP4MP, MST_BGP4MP BGP4MP_MESSAGE_AS4) -> BGP4MP_Message of bgp4mp_message(true)


struct mrt_message [top] = {
  mrt_timestamp : uint32;
  mrt_type : mrt_type;
  mrt_subtype : mrt_subtype(mrt_type);
  mrt_message : container[uint32] of mrt_message_content(mrt_type, mrt_subtype)
}
