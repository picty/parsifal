open Lwt
open Parsifal
open PTypes
open Pcap
open TlsEnums
open Getopt



let dest_port = ref 443

let options = [
  mkopt (Some 'h') "help" Usage "show this help";
  mkopt (Some 'p') "port" (IntVal dest_port) "changes the port to monitor"
]



type connection_key = {
  source : ipv4 * int;
  destination : ipv4 * int;
}
    
type segment = direction * int * string

type connection = {
  first_src_seq : int;
  first_dst_seq : int;
  segments : segment list
}

let connections : (connection_key, connection) Hashtbl.t = Hashtbl.create 100


let update_connection = function
  | { ip_payload = TCPLayer {
    tcp_payload = "" } } -> ()
    (* TODO: Handle SYN/SYN-ACK *)

  | { source_ip = src_ip;
      dest_ip = dst_ip;
      ip_payload = TCPLayer {
	source_port = src_port;
	dest_port = dst_port;
	seq = seq; ack = ack;
	tcp_payload = payload } } ->
    begin
      let key, src_seq, dst_seq, dir =
	if dst_port = !dest_port
	then Some {source = src_ip, src_port;
		   destination = dst_ip, dst_port},
	  seq, ack, ClientToServer
	else if src_port = !dest_port
	then Some {source = dst_ip, dst_port;
		   destination = src_ip, src_port},
	   ack, seq, ServerToClient
	else None, 0, 0, ClientToServer
      in match key with
      | None -> ()
      | Some k -> begin
	try
	  let c = Hashtbl.find connections k in
	  (* TODO: We do NOT handle seq wrapping *)
	  Hashtbl.replace connections k {
	    first_src_seq = min c.first_src_seq src_seq;
	    first_dst_seq = min c.first_dst_seq dst_seq;
	    segments = c.segments@[dir, src_seq, payload]
	  }
	with Not_found ->
	  Hashtbl.replace connections k {
	    first_src_seq = src_seq;
	    first_dst_seq = dst_seq;
	  segments = [dir, src_seq, payload]
	  }
      end
    end
  | _ -> ()




let handle_one_packet packet = match packet.data with
  | EthernetContent { ether_payload = IPLayer ip_layer }
  | IPContent ip_layer ->
    update_connection ip_layer
  | _ -> ()

let print_connection k _ =
  Printf.printf "%s:%d -> %s:%d\n"
    (string_of_ipv4 (fst k.source)) (snd k.source)
    (string_of_ipv4 (fst k.destination)) (snd k.destination)

let handle_one_file input =
  lwt_parse_pcap_file input >>= fun pcap ->
  List.iter handle_one_packet pcap.packets;
  Hashtbl.iter print_connection connections;
  return ()


let _ =
  try
    let args = parse_args ~progname:"extractSessions" options Sys.argv in
    let open_files = function
      | [] -> input_of_channel "(stdin)" Lwt_io.stdin >>= fun x -> return [x]
      | _ -> Lwt_list.map_s input_of_filename args
    in
    Lwt_unix.run (open_files args >>= Lwt_list.iter_s handle_one_file);
  with
    | ParsingException (e, h) -> prerr_endline (string_of_exception e h); exit 1
    | e -> print_endline (Printexc.to_string e); exit 1
