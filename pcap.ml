open Parsifal
open PTypes

struct pcap_version [top] = {
  major_version : uint16le;
  minor_version : uint16le
}

enum link_type [with_lwt; little_endian] (32, UnknownVal LinkType_Unknown) =
  | 1 -> LinkTypeEthernet
  | 101 -> LinkTypeRaw
  | 228 -> LinkTypeIPV4

struct packet [top] = {
  timestamp : uint32le;
  microseconds : uint32le;
  length_in_file : uint32le;
  length_on_the_wire : uint32le;
  data : binstring(length_in_file)
}

struct pcap_file [top] = {
  magic_number : magic["\xd4\xc3\xb2\xa1"];
  pcap_version : pcap_version;
  gmt_timezone_offset : binstring(8);
  packets_max_len : uint32le;
  link_type : link_type;
  packets : list of packet
}

let std_pcap_hdr = {
  magic_number = ();
  pcap_version = { major_version = 2; minor_version = 4 };
  gmt_timezone_offset = "\x00\x00\x00\x00\x00\x00\x00\x00";
  packets_max_len = 65535;
  link_type = LinkTypeRaw;
  packets = []
}
let std_pcap_hdr_str = dump_pcap_file std_pcap_hdr


struct tcp_layer = {
  source_port : uint16;
  dest_port : uint16;
  seq : uint32;
  ack : uint32;
  flags : uint16;
  window_size : uint16;
  tcp_checksum : uint16;
  urgent_pointer : uint16;
  tcp_payload : binstring
}

struct ip_layer = {
  version_ihl : uint8;
  type_of_service : uint8;
  total_length : uint16;
  identification : uint16;
  flags_fragment : uint16;
  ttl : uint8;
  protocol : uint8;
  ip_checksum : uint16;
  source_ip : ipv4;
  dest_ip : ipv4;
  ip_payload : tcp_layer
}

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
    tcp_payload = payload
  } in
  let ip_layer = {
    version_ihl = 0x45;
    type_of_service = 0;
    total_length = payload_len + 40;
    identification = 1;
    flags_fragment = 0;
    ttl = 64;
    protocol = 6;
    ip_checksum = 0;
    source_ip =src_ip;
    dest_ip = "\x01\x02\x03\x04";
    ip_payload = tcp_layer
  } in
  let data = dump_ip_layer ip_layer in
  let data_len = String.length data in
  {
    timestamp = 0;
    microseconds = seq;
    length_in_file = data_len;
    length_on_the_wire = data_len;
    data = data
  }
