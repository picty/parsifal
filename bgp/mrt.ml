(* Guillaume Valadon <guillaume.valadon@ssi.gouv.fr> *)
(* Olivier Levillain <olivier.levillain@ssi.gouv.fr> *)


open BgpTypes
open ParsingEngine


let pop_asn16 pc = ASN16(Int32.of_int (extract_uint16 pc))
let pop_asn32 pc = ASN32(extract_uint32_as_int32 pc)
let pop_ip4 pc = IPv4(pop_string_with_len pc 4)
let pop_ip6 pc = IPv6(pop_string_with_len pc 16)



(* From Input / MrtTools *)

(* TODO: Check if i implement what is wanted.
let nlri_to_ip raw plen address_size =
  let expand addr len =
    let n = len-(String.length addr) in
    addr ^ (String.make n (Char.chr 0))
  in
  let rec internal addr i = match i with
    | n when n == address_size -> String.sub addr (i-1) 1
    | _                        -> match (i-1)*8 <= plen && plen <= i*8 with
                                  | false -> (String.sub addr i 1) ^ (internal addr (i+1))
				  | true  -> (String.make 1 (Char.chr(int_of_char addr.[i] land (plen mod 8)))) ^
				             (internal addr (i+1))

  in internal (expand raw address_size) 0 *)

let nlri_to_ip raw plen address_size =
  if (address_size * 8) < plen || ((String.length raw) * 8) < plen
  then failwith "nlri_to_ip: invalid arguments";
  let res = String.make address_size '\x00' in
  let rec copy_bits i remaining = match remaining with
    | 0 -> res
    | 1 | 2 | 3 | 4 | 5 | 6 | 7 ->
      res.[i] <- char_of_int ((int_of_char raw.[i]) land (lnot ((2 lsl (7 - remaining)) - 1)));
      res
    | _ ->
      res.[i] <- raw.[i];
      copy_bits (i + 1) (remaining - 8)
  in copy_bits 0 plen


let get_nlri pc address_size =
  let plen_bits = pop_byte pc in
  let plen_bytes = (plen_bits + 7) / 8 in
  let prefix_raw = pop_string_with_len pc plen_bytes in
  let prefix = nlri_to_ip prefix_raw plen_bits address_size in
  match address_size with
    | 4 -> Prefix (IPv4 (prefix), plen_bits)
    | 16 -> Prefix (IPv6 (prefix), plen_bits)
    | n -> raise (MRTParsingError (Printf.sprintf "Invalid address size: %i" n))

let get_prefixes_list pc address_size wr_len =
  extract_list_fixedlen "(* TODO OL : Name ? *)" wr_len (fun new_pc -> get_nlri new_pc address_size) pc


let nlri_get_prefixes pc ip_len =
  (* This part of the NLRI BGP attributes is always at the end of the attribute.  *)
  (* TODO OL: Here, I have changed the behaviour if afi prefix is neither 1 or 2, since it is checked before *)
  let rec aux () =
    let p = get_nlri pc ip_len in
    p::(aux ())
  in
  aux ()




let parse_peers pc l =
  let rec internal l = match l with
    |0 -> []
    |_ ->
      let typ = pop_byte pc in
      let bgpid = pop_string_with_len pc 4 in
      match typ with
	| 0 ->
	  let addr = pop_ip4 pc in
	  let asn = pop_asn16 pc in
	  PeerEntry (bgpid, addr, asn)::(internal (l-1))
	| 1 ->
	  let addr = pop_ip4 pc in
	  let asn = pop_asn32 pc in
	  PeerEntry (bgpid, addr, asn)::(internal (l-1))
	| 2 ->
	  let addr = pop_ip6 pc in
	  let asn = pop_asn16 pc in
	  PeerEntry (bgpid, addr, asn)::(internal (l-1))
	| 3 ->
	  let addr = pop_ip6 pc in
	  let asn = pop_asn32 pc in
	  PeerEntry (bgpid, addr, asn)::(internal (l-1))
	| _ -> [UnknownPeerEntry(typ)]    (* TODO OL: Why don't we call internal. Should this be an exception? *)
  in internal l


let parse_peer_index_table pc =
  let bgpid = pop_string_with_len pc 4 in
  let view_name_length = extract_uint16 pc in
  let view_name = match view_name_length with 0 -> "OPT_view" | l -> pop_string_with_len pc l in
  let peer_count = extract_uint16 pc in
  PEER_INDEX_TABLE(bgpid, view_name, parse_peers pc peer_count)


let get_path_segment asn_len pc =
  let path_segment_length = pop_byte pc in
  let rec aux f = function
    | 0 -> []
    | n -> (f pc)::(aux f (n-1))
  in
  match asn_len with
    | 4 -> aux pop_asn32 path_segment_length
    | 2 -> aux pop_asn16 path_segment_length
    | n -> raise (MRTParsingError (Printf.sprintf "get_path_segment: unknown AS length: %i" n))


let rec parse_attr_as_path asn_len pc =
  try
    let path_segment_type = pop_byte pc in
    match path_segment_type with
      | 1 -> let path_segment = get_path_segment asn_len pc in
	     AS_SEQUENCE(path_segment)::(parse_attr_as_path asn_len pc)
      | 2 -> let path_segment = get_path_segment asn_len pc in
	     AS_SET(path_segment)::(parse_attr_as_path asn_len pc)
      | n -> Unknown_AS_PATH_TYPE(n)::[]
  with OutOfBounds _ -> []


let rec parse_communities pc =
  try
    let asn = extract_uint16 pc in (* Why is it a 16 bits ASN ? *)
    let value = extract_uint16 pc in
    (asn,value)::(parse_communities pc)
  with OutOfBounds _ -> []


let parse_reach_nlri_attr attr_flags afi pc =
  let gip,ip_len,afi_type = match afi with
    | 1 -> (pop_ip4,4,INET)
    | 2 -> (pop_ip6,16,INET6)
    | n -> raise (MRTParsingError (Printf.sprintf "Unknown AFI: %i" n)) in
  let safi = pop_byte pc in (* 1: UNICAST forwarding 2: MULTICAST forwarding *)
  let safi_type = match safi with 1 -> UNICAST_FORWARDING | 2 -> MULTICAST_FORWARDING | _ -> UnknownSAFIType(safi) in
  let next_hop_len = pop_byte pc in
  let ip_list = extract_list_fixedlen "(* TODO OL: Name ? *)" (next_hop_len/ip_len) gip pc in
  let reserved = pop_byte pc in
  match reserved with
    | 0 -> BGPAttributeMP_REACH_NLRI(attr_flags, afi_type, safi_type, ip_list,
				     nlri_get_prefixes pc ip_len)
    | _ -> raise (MRTParsingError ("reserved != 0"))


let parse_reach_nlri_attr_abbreviated attr_flags pc =
  let gip,ip_len = pop_ip6,16 in
  let next_hop_len = pop_byte pc in
  let ip_list = extract_list_fixedlen "(* TODO OL: Name ? *)" (next_hop_len/ip_len) gip pc in
  BGPAttributeMP_REACH_NLRI_abbreviated(attr_flags, ip_list)


let parse_unreach_nlri_attr attr_flags afi pc =
  let ip_len,afi_type = match afi with
    | 1 -> (4,INET)
    | 2 -> (16,INET6)
    | n -> raise (MRTParsingError (Printf.sprintf "Unknown AFI: %i" n)) in
  let safi = pop_byte pc in (* 1: UNICAST forwarding 2: MULTICAST forwarding *)
  let safi_type = match safi with 1 -> UNICAST_FORWARDING | 2 -> MULTICAST_FORWARDING | _ -> UnknownSAFIType(safi)
  in
  BGPAttributeMP_UNREACH_NLRI(attr_flags, afi_type, safi_type,
			      nlri_get_prefixes pc ip_len)


let parse_bgp_attributes ?(asn_len=4) pc get_ip =
  let rec internal () =
    let attr_flags = pop_byte pc in
    let attr_type = pop_byte pc in
    let extended_length = (attr_flags land 16) == 16 in
    let attr_len = match extended_length with false -> pop_byte pc | true -> extract_uint16 pc in
    let new_pc = go_down pc "(* TODO OL: Name ? *)" attr_len in
    let bgp_attribute = match attr_type with
      | 1 -> let origin = pop_byte new_pc in
	     BGPAttributeORIGIN(attr_flags, origin)

      | 2 -> let path_segments = parse_attr_as_path asn_len new_pc in (* XXX: 2 bytes ASN ?!? *)
	     BGPAttributeAS_PATH(attr_flags, path_segments)

      | 3 -> let next_hop = pop_string_with_len new_pc 4 in  (* TODO: Should this be an ip address ? *)
	     BGPAttributeNEXT_HOP(attr_flags, next_hop)

      | 4 -> let med = extract_uint32 new_pc in
	     BGPAttributeMULTI_EXIT_DISC(attr_flags, med)

      | 6 -> BGPAttributeATOMIC_AGGREGATE(attr_flags)

      | 7 -> let asn = match asn_len with
		       | 4 -> extract_uint32 new_pc   (* TODO OL: Should not this be an ASN16 or ASN32 ? *)
		       | 2 -> extract_uint16 new_pc
		       | n -> raise (MRTParsingError (Printf.sprintf "parse_bgp_attribues: unknown AS length: %i" n))
	     in
	     let ip = pop_string_with_len new_pc 4 in  (* TODO: Should this be an ip address ? *)
	     BGPAttributeAGGREGATOR(attr_flags, asn, ip)

      | 8 -> BGPAttributeCOMMUNITY(attr_flags, parse_communities new_pc)

      | 14 -> let afi = extract_uint16 new_pc in (* RFC 4760 defines this BGP attribute *)
	      let reach_nlri = match afi with
			     | n when n <= 2 -> parse_reach_nlri_attr attr_flags n new_pc
			     | _             -> parse_reach_nlri_attr_abbreviated attr_flags new_pc
	      in reach_nlri

      | 15 -> let afi = extract_uint16 new_pc in (* RFC 4760 defines this BGP attribute *)
	      let unreach_nlri = parse_unreach_nlri_attr attr_flags afi new_pc
	      in unreach_nlri

      | 17 -> let path_segments = parse_attr_as_path 4 new_pc in
	      BGPAttributeAS4_PATH(attr_flags, path_segments)

      | _ -> let _ = pop_string_with_len new_pc attr_len in
	     BGPAttributeUnknown(attr_flags, attr_type)
      in
      bgp_attribute::(internal ())

    in
      try internal ()
      with OutOfBounds _ -> []


let rec parse_rib_entries pc count get_ip =
  let peer_index = extract_uint16 pc in
  let timestamp = extract_uint32 pc in
  let attr_len = extract_uint16 pc in
  let new_pc = go_down pc "(* TODO OL: Name ? *)" attr_len in
  let ribentry = RIBEntry(peer_index, timestamp, attr_len, parse_bgp_attributes new_pc get_ip) in
  match count with
    | 1 -> [ribentry]
    | _ -> ribentry::(parse_rib_entries pc (count-1) get_ip)

let parse_rib_ipv4_unicast pc =
  let seq = extract_uint32 pc in
  let prefix = get_nlri pc 4 in
  let entry_count = extract_uint16 pc in
  RIB_IPV4_UNICAST(seq, prefix, parse_rib_entries pc entry_count pop_ip4)


let parse_rib_ipv6_unicast pc =
  let seq = extract_uint32 pc in
  let prefix = get_nlri pc 16 in
  let entry_count = extract_uint16 pc in
  RIB_IPV6_UNICAST(seq, prefix, parse_rib_entries pc entry_count pop_ip6)


let parse_bgp_update pc message_len gip iplen asn_len =
  let wr_len = extract_uint16 pc in (* wr == Withdraw Routes *)
  let wr_prefixes = get_prefixes_list pc iplen wr_len in
  let attr_len = extract_uint16 pc in
  let new_pc = go_down pc "(* TODO OL: Name? *)" attr_len in
  let attr = parse_bgp_attributes ~asn_len:asn_len new_pc gip in
  (* RFC4271: NLRI length: UPDATE message Length - 23 - Total Path Attributes Length - Withdrawn Routes Length *)
  let nlri_len = message_len - 23 - attr_len - wr_len in
  let nlri_prefixes = get_prefixes_list pc iplen nlri_len in
  BGP_UPDATE(wr_prefixes, attr, nlri_prefixes)


let _parse_bgp4mp_message is_as4 pc =
  let mk_msg_as4 (a,b,c,d,e,f) = MESSAGE_AS4 (a,b,c,d,e,f)
  and mk_msg (a,b,c,d,e,f) = MESSAGE (a,b,c,d,e,f) in
  let pop_asn, mk_msg, msg_len =
    if is_as4
    then pop_asn32, mk_msg_as4, 4
    else pop_asn16, mk_msg, 2
  in

  let peeras = pop_asn pc in
  let localas = pop_asn pc in
  let interface_index = extract_uint16 pc in
  let afi = extract_uint16 pc in
  let gip,ip_len = match afi with
    | 1 -> pop_ip4, 4
    | 2 -> pop_ip6, 16
    | n -> raise (MRTParsingError (Printf.sprintf "Unknown AFI: %i" n)) in
  let peerip = gip pc in
  let localip = gip pc in
  (* The entire BGP message is included in the BGP Message field. *)
  let marker = pop_string_with_len pc 16 in
  let _ = match marker with
    | "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" -> ()
    | _ -> raise (MRTParsingError "Marker is not valid !") in
  let message_size = extract_uint16 pc in
  let message_type = pop_byte pc in
  let bgp_message = match message_type with
    | 2 -> parse_bgp_update pc message_size gip ip_len msg_len
    | 4 -> BGP_KEEPALIVE
    | n -> drop_bytes pc (message_size-19);
           BGP_UNKNOWN(n)
  in
  mk_msg (peeras, localas, interface_index, peerip, localip, bgp_message)


let parse_bgp4mp_message_as4 = _parse_bgp4mp_message true
let parse_bgp4mp_message = _parse_bgp4mp_message false


let mrt_hdr pc =
  let timestamp = extract_uint32 pc in
  let typ = extract_uint16 pc in
  let subtyp = extract_uint16 pc in
  let length = extract_uint32 pc in
  let new_pc = go_down pc "MRT Header" length in
  match typ, subtyp with
    | 13,1 -> MRTHeader(timestamp, TABLE_DUMP_v2(parse_peer_index_table new_pc))
    | 13,2 -> MRTHeader(timestamp, TABLE_DUMP_v2(parse_rib_ipv4_unicast new_pc))
    | 13,4 -> MRTHeader(timestamp, TABLE_DUMP_v2(parse_rib_ipv6_unicast new_pc))
    | 16,1 -> MRTHeader(timestamp, BGP4MP(parse_bgp4mp_message new_pc))
    | 16,4 -> MRTHeader(timestamp, BGP4MP(parse_bgp4mp_message_as4 new_pc))
    | t,s  -> let message = pop_string_with_len new_pc length in
	      MRTHeader(timestamp, Unknown(t, s, message))
