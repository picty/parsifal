open BasePTypes
open PTypes
open Dns


(* TODO: ICMP *)
union udp_service [enrich] (UnparsedProtocol) =
  | 53, _
  | _, 53 -> DNS of dns_message

struct udp_layer = {
  udp_source_port : uint16;
  udp_dest_port : uint16;
  udp_len : uint16;
  udp_checksum : uint16;
  udp_payload : container(udp_len - 8) of udp_service(udp_source_port, udp_dest_port)
}


struct tcp_layer = {
  source_port : uint16;
  dest_port : uint16;
  seq : uint32;
  ack : uint32;
  flags : uint16;
  window_size : uint16;
  tcp_checksum : uint16;
  urgent_pointer : uint16;
  options : binstring (((flags lsr 12) * 4) - 20);
  tcp_payload : binstring
}


(* TODO: ICMP *)
enum protocol (8, UnknownVal UnknownProtocol) =
  | 6 -> ProtocolTCP
  | 17 -> ProtocolUDP

union ip_payload [enrich] (UnparsedProtocol) =
  | ProtocolTCP -> TCPLayer of tcp_layer
  | ProtocolUDP -> UDPLayer of udp_layer

let parse_ip_payload protocol input =
  match Parsifal.try_parse (parse_ip_payload protocol) input with
  | Some res -> res
  | None -> UnparsedProtocol (parse_rem_string input)

struct ip_layer = {
  version_ihl : uint8;
  type_of_service : uint8;
  total_length : uint16;
  identification : uint16;
  flags_fragment : uint16;
  ttl : uint8;
  protocol : protocol;
  ip_checksum : uint16;
  source_ip : ipv4;
  dest_ip : ipv4;
  ip_payload : container(total_length - 20) of ip_payload(protocol)
}


enum ether_type (16, UnknownVal UnknownEtherType) =
  | 0x0800 -> EtherTypeIPv4

union ether_payload [enrich] (UnparsedEtherPayload) =
  | EtherTypeIPv4 -> IPLayer of ip_layer

let parse_ether_payload ether_type input =
  match Parsifal.try_parse (parse_ether_payload ether_type) input with
  | Some res -> res
  | None -> UnparsedEtherPayload (parse_rem_string input)

struct ethernet_layer = {
  source_mac : binstring(6);
  destination_mac : binstring(6);
  ether_type : ether_type;
  ether_payload : ether_payload (ether_type);
  trailing_bits : binstring
}


struct pcap_version [top] = {
  major_version : uint16le;
  minor_version : uint16le
}


enum link_type [with_lwt; little_endian] (32, UnknownVal LinkType_Unknown) =
  | 1 -> LinkTypeEthernet
  | 101 -> LinkTypeRaw
  | 228 -> LinkTypeIPV4

union packet_content [enrich] (UnknownPacketContent) =
  | LinkTypeEthernet -> EthernetContent of ethernet_layer
  | LinkTypeIPV4 -> IPContent of ip_layer

struct packet [param link_type; top] = {
  timestamp : uint32le;
  microseconds : uint32le;
  length_in_file : uint32le;
  length_on_the_wire : uint32le;
  data : container(length_in_file) of packet_content(link_type)
}


struct pcap_file [top] = {
  magic_number : magic("\xd4\xc3\xb2\xa1");
  pcap_version : pcap_version;
  gmt_timezone_offset : binstring(8);
  packets_max_len : uint32le;
  link_type : link_type;
  packets : list of packet(link_type)
}



let std_pcap_hdr = {
  magic_number = "\xd4\xc3\xb2\xa1";
  pcap_version = { major_version = 2; minor_version = 4 };
  gmt_timezone_offset = "\x00\x00\x00\x00\x00\x00\x00\x00";
  packets_max_len = 65535;
  link_type = LinkTypeRaw;
  packets = []
}
let std_pcap_hdr_str = exact_dump_pcap_file std_pcap_hdr


let mk_packet src_ip src_port payload seq =
  let payload_len = String.length payload in
  let tcp_layer = {
    source_port = src_port;
    dest_port = 12345;
    seq = seq;
    ack = 0;
    flags = 0x5000;
    window_size = 8192;
    tcp_checksum = 0;
    urgent_pointer = 0;
    options = "";
    tcp_payload = payload
  } in
  let ip_layer = {
    version_ihl = 0x45;
    type_of_service = 0;
    total_length = payload_len + 40;
    identification = 1;
    flags_fragment = 0;
    ttl = 64;
    protocol = ProtocolTCP;
    ip_checksum = 0;
    source_ip =src_ip;
    dest_ip = "\x01\x02\x03\x04";
    ip_payload = TCPLayer tcp_layer
  } in
  let data = Parsifal.exact_dump dump_ip_layer ip_layer in
  let data_len = String.length data in
  {
    timestamp = 0;
    microseconds = seq;
    length_in_file = data_len;
    length_on_the_wire = data_len;
    data = IPContent ip_layer
  }
