open Lwt
open Parsifal
open PTypes
open Asn1PTypes
open AnswerDump
open TlsEnums
open Tls
open Getopt
open X509Basics
open X509

type action = IP | Dump | All | Suite | SKE | Subject | ServerRandom | Scapy | Pcap
let action = ref IP
let verbose = ref false
let raw_records = ref false
let filter_ip = ref ""

let options = [
  mkopt (Some 'h') "help" Usage "show this help";
  mkopt (Some 'v') "verbose" (Set verbose) "print more info to stderr";

  mkopt None "raw-records" (Set raw_records) "show raw records (do not try to reassemble them)";

  mkopt (Some 'a') "all" (TrivialFun (fun () -> action := All)) "show all the information and records of an answer";
  mkopt (Some 'I') "ip" (TrivialFun (fun () -> action := IP)) "only show the IP of the answers";
  mkopt (Some 'D') "dump" (TrivialFun (fun () -> action := Dump)) "dumps the answers";
  mkopt (Some 's') "ciphersuite" (TrivialFun (fun () -> action := Suite)) "only show the ciphersuite chosen";
  mkopt (Some 'S') "ske" (TrivialFun (fun () -> action := SKE)) "only show information relative to ServerKeyExchange";
  mkopt None "server-random" (TrivialFun (fun () -> action := ServerRandom)) "only output the server random";
  mkopt None "scapy-style" (TrivialFun (fun () -> action := Scapy)) "outputs the records as independant scapy-style packets";
  mkopt None "output-pcap" (TrivialFun (fun () -> action := Pcap)) "export the answer as a PCAP";
  mkopt None "cn" (TrivialFun (fun () -> action := Subject)) "show the subect";

  mkopt None "filter-ip" (StringVal filter_ip) "only print info regarding this ip"
]

let getopt_params = {
  default_progname = "test_answerDump";
  options = options;
  postprocess_funs = [];
}


let input_of_filename filename =
  Lwt_unix.openfile filename [Unix.O_RDONLY] 0 >>= fun fd ->
  input_of_fd filename fd

let parse_all_records answer =
  let rec read_records accu i =
    if not (eos i)
    then begin
      let next = (parse_tls_record None i) in
      read_records (next::accu) i
    end else List.rev accu
  in
  (* TODO: Move this function in TlsUtil? *)
  let rec split_records accu ctx str_input recs = match str_input, recs with
    | None, [] -> List.rev accu, ctx, false
    | None, record::r ->
      let record_input = input_of_string ~enrich:true (string_of_ipv4 answer.ip) (dump_record_content record.record_content) in
      let cursor = record.content_type, record.record_version, record_input in
      split_records accu ctx (Some cursor) r
    | Some (ct, v, i), _ ->
      if eos i then split_records accu ctx None recs
      else begin
        try
          let next_content = parse_record_content ctx ct i in
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

        with _ -> List.rev accu, ctx, true
      end
  in

  let answer_input = input_of_string (string_of_ipv4 answer.ip) answer.content in
  enrich_record_content := false;
  try
    if !raw_records
    then read_records [] answer_input, None, false
    else split_records [] None None (TlsUtil.merge_records ~enrich:false (read_records [] answer_input))
  with _ -> [], None, true
  


let rec handle_answer answer =
  let ip = string_of_ipv4 answer.ip in
  let this_one, again =
    if !filter_ip = ""
    then true, true
    else if !filter_ip = ip
    then true, false
    else false, true
  in
  if this_one then begin
    match !action with
      | IP -> print_endline ip
      | Dump -> print_string (dump_answer_dump answer)
      | All ->
        let records, _, error = parse_all_records answer in
        print_endline ip;
        List.iter (fun r -> print_endline (print_tls_record ~indent:"  " r)) records;
        if error then print_endline "  ERROR"
      | Suite ->
        let _, ctx, _ = parse_all_records answer in
        let cs = match ctx with
          | None -> if !verbose then (Some "ERROR") else None
          | Some ctx -> Some (string_of_ciphersuite ctx.future.s_ciphersuite.suite_name)
        in
        begin
          match cs with
            | None -> ()
            | Some s -> Printf.printf "%s: %s\n" ip s
        end
      | SKE ->
        let _, ctx, _ = parse_all_records answer in
        let ske = match ctx with
          | None -> if !verbose then (Some "ERROR") else None
          | Some { future = { s_server_key_exchange = (SKE_DHE { params = params } ) } } ->
            Some (Printf.sprintf "%s,%s,%s" (hexdump params.dh_p) (hexdump params.dh_g) (hexdump params.dh_Ys))
          | Some { future = { s_server_key_exchange = (Unparsed_SKEContent "" ) } } ->
            if !verbose then (Some "NO_SKE") else None
          | Some _ -> if !verbose then (Some "NOT PARSED YET") else None
        in
        begin
          match ske with
            | None -> ()
            | Some s -> Printf.printf "%s: %s\n" ip s
        end
      | ServerRandom ->
        let records, _, _ = parse_all_records answer in
        begin
	  match records with
          | { content_type = CT_Handshake;
              record_content = Handshake {
                handshake_type = HT_ServerHello;
                handshake_content = ServerHello {server_random = r} }}::_
	    -> Printf.printf "%s: %s\n" ip (hexdump r)
          | _ -> ()
        end;
      | Scapy ->
	let records, _, _ = parse_all_records answer in
	let rec convert_to_scapy (len, ps) = function
	  | [] -> List.rev ps
	  | r::rs ->
	    let dump = dump_tls_record r in
	    let new_p =
	      Printf.sprintf "IP(src=\"%s\")/TCP(sport=%d,dport=12345,seq=%d,flags=\"\")/(\"%s\".decode(\"hex\"))"
		ip answer.port len (hexdump dump)
	    in
	    convert_to_scapy (len + (String.length dump), new_p::ps) rs
	in
	Printf.printf "ps = [%s]\n" (String.concat ",\n  " (convert_to_scapy (0, []) records))
      | Pcap ->
	let records, _, _ = parse_all_records answer in
	let rec convert_to_pcap len ps = function
	  | [] -> ()
	  | r::rs ->
	    let dump = dump_tls_record r in
	    let new_p = Pcap.mk_packet answer.ip answer.port dump len in
	    print_string (Pcap.dump_packet new_p);
	    convert_to_pcap (len + (String.length dump)) (new_p::ps) rs
	in
	convert_to_pcap 0 [] records
      | Subject ->
        let records, _, _ = parse_all_records answer in
        let rec extractSubjectOfFirstCert = function
          | [] -> None
          | { content_type = CT_Handshake;
              record_content = Handshake {
                handshake_type = HT_Certificate;
                handshake_content = Certificate ((UnparsedCertificate cert_string)::_) }}::_ ->
            begin
              try
                let cert = parse_certificate (input_of_string "" cert_string) in
                Some (String.concat ", " (List.map string_of_atv (List.flatten cert.tbsCertificate.subject)))
              with _ -> None
                  end
          | _::r -> extractSubjectOfFirstCert r
        in
        begin
          match extractSubjectOfFirstCert records with
            | None -> ()
            | Some subject -> Printf.printf "%s: %s\n" ip subject
        end;
  end;
  return again

let rec handle_one_file input =
  lwt_try_parse lwt_parse_answer_dump input >>= function
    | None -> return ()
    | Some answer ->
      handle_answer answer >>= fun again ->
      if again then handle_one_file input else return ()

let _ =
  try
    let args = parse_args getopt_params Sys.argv in
    if !action = Pcap
    then print_string (Pcap.std_pcap_hdr_str);
    let open_files = function
      | [] -> input_of_channel "(stdin)" Lwt_io.stdin >>= fun x -> return [x]
      | _ -> Lwt_list.map_s input_of_filename args
    in
    Lwt_unix.run (open_files args >>= Lwt_list.iter_s handle_one_file);
  with
    | End_of_file -> ()
    | e -> print_endline (Printexc.to_string e)

