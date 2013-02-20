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
