open Lwt
open Parsifal
open PTypes
open Pcap
open TlsEnums
open Tls
open Getopt



let dest_port = ref 443
let verbose = ref false
let print_all = ref false

let enrich_style = ref DefaultEnrich
let set_enrich_level l =
  if l > 0 then begin
    enrich_style := EnrichLevel l;
    ActionDone
  end else ShowUsage (Some "enrich level should be a positive number.")
let update_enrich_level l =
  let new_style = match !enrich_style with
    | DefaultEnrich | NeverEnrich -> EnrichLevel l
    | EnrichLevel x -> EnrichLevel (max x l)
    | AlwaysEnrich -> AlwaysEnrich
  in enrich_style := new_style


(* TODO: Add more features
   - get
   - anserType
   - filter-ip
   - clear-only *)
(* TODO: Improve TCP/IP handling *)

let options = [
  mkopt (Some 'h') "help" Usage "show this help";
  mkopt (Some 'p') "port" (IntVal dest_port) "changes the port to monitor";
  mkopt (Some 'a') "all" (Set print_all) "print all the SSL messages";

  mkopt (Some 'v') "verbose" (Set verbose) "print more info to stderr";

  mkopt None "always-enrich" (TrivialFun (fun () -> enrich_style := AlwaysEnrich)) "always enrich the structure parsed";
  mkopt None "never-enrich" (TrivialFun (fun () -> enrich_style := NeverEnrich)) "never enrich the structure parsed";
  mkopt None "enrich-level" (IntFun set_enrich_level) "enrich the structure parsed up to a certain level";
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




let parse_all_records enrich input =
  let rec read_records accu i =
    if not (eos i)
    then begin
      match try_parse (parse_tls_record None) i with
      | Some next -> read_records (next::accu) i
      | None -> List.rev accu (* Signal error ?! *)
    end else List.rev accu
  in

  (* TODO: Move this function in TlsUtil? *)
  let rec split_records accu ctx str_input recs = match str_input, recs with
    | None, [] -> List.rev accu, ctx
    | None, record::r ->
      let record_input =
	input_of_string ~verbose:(!verbose) ~enrich:enrich (input.cur_name)
	  (exact_dump_record_content record.record_content)
      in
      let cursor = record.content_type, record.record_version, record_input in
      split_records accu ctx (Some cursor) r
    | Some (ct, v, i), _ ->
      if eos i then split_records accu ctx None recs
      else begin
        match try_parse (parse_record_content ctx ct) i with
        | Some next_content ->
          let next_record = {
            content_type = ct;
            record_version = v;
            record_content = next_content;
          } in
          begin
            match ctx, next_content with
              | None, Handshake {handshake_content = ServerHello sh} ->
                let real_ctx = empty_context () in
                TlsEngine.update_with_server_hello real_ctx sh;
                split_records (next_record::accu) (Some real_ctx) str_input recs
              | Some c, Handshake {handshake_content = ServerKeyExchange ske} ->
                TlsEngine.update_with_server_key_exchange c ske;
                split_records (next_record::accu) ctx str_input recs
              | _ -> split_records (next_record::accu) ctx str_input recs
          end;
        | None ->
	  let remaining_stuff = {
	    content_type = ct;
	    record_version = v;
	    record_content = Unparsed_Record (BasePTypes.parse_rem_string i)
	  } in split_records (remaining_stuff::accu) ctx None recs
      end
  in

  enrich_record_content := false;
  let raw_recs = read_records [] input in
  split_records [] None None (TlsUtil.merge_records ~verbose:(!verbose) ~enrich:NeverEnrich raw_recs)



let print_all_connection k c =
  (* TODO: Improve this stuff... *)
  let rec trivial_aggregate = function
    | [] -> []
    | (dir, _, seg)::ss ->
      match trivial_aggregate ss with
      | [] -> [dir, seg]
      | ((dir', seg')::r) as l ->
	if (dir = dir')
	then (dir, seg ^ seg')::r
	else (dir, seg)::l
  in

  let cname = Printf.sprintf "%s:%d -> %s:%d\n"
    (string_of_ipv4 (fst k.source)) (snd k.source)
    (string_of_ipv4 (fst k.destination)) (snd k.destination)
  in

  print_endline cname;
  let segs = String.concat "" (List.map snd (trivial_aggregate c.segments)) in
  let records, _ = parse_all_records !enrich_style (input_of_string cname segs) in
  List.iter (fun r -> print_endline (print_value ~verbose:!verbose ~indent:"  " (value_of_tls_record r))) records;
  print_newline ()


let print_connection k _ =
  Printf.printf "%s:%d -> %s:%d\n"
    (string_of_ipv4 (fst k.source)) (snd k.source)
    (string_of_ipv4 (fst k.destination)) (snd k.destination)

let handle_one_packet packet = match packet.data with
  | EthernetContent { ether_payload = IPLayer ip_layer }
  | IPContent ip_layer ->
    update_connection ip_layer
  | _ -> ()

let handle_one_file input =
  lwt_parse_pcap_file input >>= fun pcap ->
  List.iter handle_one_packet pcap.packets;
  Hashtbl.iter (if !print_all then print_all_connection else print_connection) connections;
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
