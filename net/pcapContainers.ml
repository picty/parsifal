open Parsifal
open BasePTypes
open PTypes
open Pcap


(* TODO: All this should be rewritten from scratch                  *)
(*       because of lots of shortcuts in the current implementation *)

type direction = ClientToServer | ServerToClient
let string_of_direction = function ClientToServer -> "C->S" | ServerToClient -> "S->C"

type connection_key = {
  source : ipv4 * int;
  destination : ipv4 * int;
}
let string_of_connexion_key k =
  Printf.sprintf "%s:%d -> %s:%d\n"
    (string_of_ipv4 (fst k.source)) (snd k.source)
    (string_of_ipv4 (fst k.destination)) (snd k.destination)

type segment = direction * int * int * string


type 'a tcp_container = (connection_key * (direction * 'a) list) list

let parse_tcp_container (expected_dest_port : int) (_name : string)
                        (parse_fun : string_input -> 'a)
                        (input : string_input) : 'a tcp_container =
  let connections : (connection_key, segment list) Hashtbl.t = Hashtbl.create 100 in

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
	let key, dir =
	  if dst_port = expected_dest_port
	  then Some {source = src_ip, src_port;
		     destination = dst_ip, dst_port},
	    ClientToServer
	  else if src_port = expected_dest_port
	  then Some {source = dst_ip, dst_port;
		     destination = src_ip, src_port},
	    ServerToClient
	  else None, ClientToServer
	in match key with
	| None -> ()
	| Some k -> begin
	  try
	    let c = Hashtbl.find connections k in
	    Hashtbl.replace connections k (c@[dir, seq, ack, payload])
	  with Not_found ->
	    Hashtbl.replace connections k [dir, seq, ack, payload]
	end
      end
    | _ -> ()
  in

  let handle_one_packet packet = match packet.data with
    | EthernetContent { ether_payload = IPLayer ip_layer }
    | IPContent ip_layer ->
      update_connection ip_layer
    | _ -> ()
  in

  let result = ref [] in


  let handle_one_connection k c =

    (* TODO: Improve this function (it does not take segment overlapping into account *)
    let aggregate segs =
      let extract_first_segment = function
	(* TODO: Other strategies are possible (by using SYN/SYN-ACK/ACK packets)... *)
	| [] -> failwith "Internal error: segment list should not be empty"
	| f::r -> f, r
      in
      let rec find_next_seg leftover accu ((cur_dir, next_seq, next_ack, cur_payload) as cur_seg) = function
        (* TODO: What should we do with leftover here? *)
	| [] -> List.rev ((cur_dir, cur_payload)::accu)
	| ((dir, seq, ack, payload) as seg)::r ->
	  if dir = cur_dir && next_seq = seq && next_ack = ack
	  then find_next_seg [] accu
	    (dir, seq + String.length payload, ack, cur_payload^payload)
	    (List.rev_append leftover r)
	  else if dir <> cur_dir && next_ack = seq && next_seq = ack
	  then find_next_seg [] ((cur_dir, cur_payload)::accu)
	    (dir, seq + String.length payload, ack, payload)
	    (List.rev_append leftover r)
	  else find_next_seg (seg::leftover) accu cur_seg r
      in

      let (dir, seq, ack, p), other_segs = extract_first_segment segs in
      find_next_seg [] [] (dir, seq + String.length p, ack, p) other_segs
    in

    let cname = string_of_connexion_key k in
    let segs = aggregate c in
    let parse_aggregate (dir, payload) =
      let new_input = get_in_container input cname payload in
      let res = parse_rem_list "tcp_container" parse_fun new_input in
      check_empty_input true new_input;
      List.map (fun x -> dir, x) res
    in
    let conn_res = k, List.flatten (List.map parse_aggregate segs) in
    result := conn_res::(!result)
  in

  let pcap = parse_pcap_file input in
  List.iter handle_one_packet pcap.packets;
  Hashtbl.iter handle_one_connection connections;
  List.rev !result


let dump_tcp_container _dump_fun _o = not_implemented "dump_tcp_container"

let value_of_tcp_connexion value_of_fun (k, segs) =
  let value_of_one_aggregate (d, p) = VRecord [
    "@name", VString ("tcp_aggregate", false);
    "direction", VString (string_of_direction d, false);
    "payload", value_of_fun p
  ] in VRecord [
    "@name", VString ("tcp_connexion", false);
    "src", value_of_ipv4 (fst k.source);
    "src_port", VSimpleInt (snd k.source);
    "dst", value_of_ipv4 (fst k.destination);
    "dst_port", VSimpleInt (snd k.destination);
    "data", VList (List.map value_of_one_aggregate segs)
  ]

let value_of_tcp_container value_of_fun = value_of_list (value_of_tcp_connexion value_of_fun)



type 'a udp_container = (connection_key * (direction * 'a) list) list

let parse_udp_container (expected_dest_port : int) (_name : string)
                        (parse_fun : string_input -> 'a)
                        (input : string_input) : 'a udp_container =
  let connections : (connection_key, (direction * string) list) Hashtbl.t = Hashtbl.create 100 in

  let update_connection = function
    | { source_ip = src_ip;
	dest_ip = dst_ip;
	ip_payload = UDPLayer {
	  udp_source_port = src_port;
	  udp_dest_port = dst_port;
	  udp_payload = payload } } ->
      begin
	let key, dir =
	  if dst_port = expected_dest_port
	  then Some {source = src_ip, src_port;
		     destination = dst_ip, dst_port},
	    ClientToServer
	  else if src_port = expected_dest_port
	  then Some {source = dst_ip, dst_port;
		     destination = src_ip, src_port},
	    ServerToClient
	  else None, ClientToServer
	in match key with
	| None -> ()
	| Some k -> begin
	  try
	    let c = Hashtbl.find connections k in
	    Hashtbl.replace connections k (c@[dir, exact_dump dump_udp_service payload])
	  with Not_found ->
	    Hashtbl.replace connections k [dir, exact_dump dump_udp_service payload]
	end
      end
    | _ -> ()
  in

  let handle_one_packet packet = match packet.data with
    | EthernetContent { ether_payload = IPLayer ip_layer }
    | IPContent ip_layer ->
      update_connection ip_layer
    | _ -> ()
  in

  let result = ref [] in

  let handle_one_connection k c =
    let c2s = string_of_connexion_key k
    and s2c = Printf.sprintf "%s:%d -> %s:%d\n"
      (string_of_ipv4 (fst k.destination)) (snd k.destination)
      (string_of_ipv4 (fst k.source)) (snd k.source)
    in

    let handle_one_datagram (dir, s) =
      let cname = match dir with
	| ClientToServer -> c2s
	| ServerToClient -> s2c
      in
      let new_input = get_in_container input cname s in
      let res = dir, exact_parse parse_fun new_input in
      check_empty_input true new_input;
      res
    in
    let conn_res = k, List.map handle_one_datagram c in
    result := conn_res::(!result)
  in

  enrich_udp_service := false;
  let pcap = parse_pcap_file input in
  List.iter handle_one_packet pcap.packets;
  Hashtbl.iter handle_one_connection connections;
  List.rev !result


let dump_udp_container _dump_fun _o = not_implemented "NotImplemented: dump_tcp_container"

let value_of_udp_connexion value_of_fun (k, segs) =
  let value_of_one_aggregate (d, p) = VRecord [
    "@name", VString ("udp_datagram", false);
    "direction", VString (string_of_direction d, false);
    "payload", value_of_fun p
  ] in VRecord [
    "@name", VString ("udp_connexion", false);
    "src", value_of_ipv4 (fst k.source);
    "src_port", VSimpleInt (snd k.source);
    "dst", value_of_ipv4 (fst k.destination);
    "dst_port", VSimpleInt (snd k.destination);
    "data", VList (List.map value_of_one_aggregate segs)
  ]

let value_of_udp_container value_of_fun = value_of_list (value_of_udp_connexion value_of_fun)


