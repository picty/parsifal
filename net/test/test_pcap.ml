open Lwt
open Parsifal
open PTypes
open Pcap
open Getopt

let show_transport_only = ref false

let options = [
  mkopt (Some 'h') "help" Usage "show this help";
  mkopt (Some 'T') "transport layer only" (Set show_transport_only) "TCP/UDP content";
]


let show_one_packet packet = match packet.data with
  | EthernetContent {
    ether_payload = IPLayer {
      ip_payload = TCPLayer {
	tcp_payload = ""
      }
    }
  }    
  | IPContent {
    ip_payload = TCPLayer {
      tcp_payload = ""
    }
  } -> ()
  | EthernetContent {
    ether_payload = IPLayer {
      source_ip = src_ip;
      dest_ip = dst_ip;
      ip_payload = TCPLayer {
	source_port = src_port;
	dest_port = dst_port;
	tcp_payload = payload
      }
    }
  }    
  | IPContent {
    source_ip = src_ip;
    dest_ip = dst_ip;
    ip_payload = TCPLayer {
      source_port = src_port;
      dest_port = dst_port;
      tcp_payload = payload
    }
  } ->
    Printf.printf "%s:%d -> %s:%d { %s }\n"
      (string_of_ipv4 src_ip) src_port
      (string_of_ipv4 dst_ip) dst_port (hexdump payload)

  | EthernetContent {
    ether_payload = IPLayer {
      source_ip = src_ip;
      dest_ip = dst_ip;
      ip_payload = UDPLayer {
	udp_source_port = src_port;
	udp_dest_port = dst_port;
	udp_payload = payload
      }
    }
  }
  | IPContent {
    source_ip = src_ip;
    dest_ip = dst_ip;
    ip_payload = UDPLayer {
      udp_source_port = src_port;
      udp_dest_port = dst_port;
      udp_payload = payload
    }
  } ->
    Printf.printf "%s:%d -> %s:%d { %s }\n"
      (string_of_ipv4 src_ip) src_port
      (string_of_ipv4 dst_ip) dst_port (print_value (value_of_udp_service payload))
  | _ -> ()

let show_packets pcap =
  List.iter show_one_packet pcap.packets


let handle_one_file input =
  lwt_parse_pcap_file input >>= fun pcap ->
  if !show_transport_only
  then show_packets pcap
  else print_string (print_value (value_of_pcap_file pcap));
  return ()


let _ =
  try
    let args = parse_args ~progname:"test_pcap" options Sys.argv in
    let open_files = function
      | [] -> input_of_channel "(stdin)" Lwt_io.stdin >>= fun x -> return [x]
      | _ -> Lwt_list.map_s input_of_filename args
    in
    Lwt_unix.run (open_files args >>= Lwt_list.iter_s handle_one_file);
  with
    | ParsingException (e, h) -> prerr_endline (string_of_exception e h); exit 1
    | e -> print_endline (Printexc.to_string e); exit 1
