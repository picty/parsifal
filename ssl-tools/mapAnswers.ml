open Lwt
open LwtUtil
open Parsifal
open PTypes
open AnswerDump
open TlsEnums
open Getopt
open X509Basics
open X509
open Ssl2
open Tls
open AnswerDumpUtil


type action = IP | Dump | All | AllJson | Suite | SKE | Subject | ServerRandom | Scapy | Pcap
              | AnswerType | RecordTypes | Get | VersionACSAC | SuiteACSAC | SaveCertificates of string
              | OutputCerts | HTTPNames
let action = ref IP
let verbose = ref false
let maxlen = ref (Some 70)
let filter_ip = ref ""
let filter_ip_hash = ref None
let junk_length = ref 16
let path = ref []
let v2_answer_dump = ref true

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

let do_get_action path_str =
  action := Get;
  path := (!path)@[path_str];
  ActionDone

let load_filter_ips_from_file filename =
  let h = match !filter_ip_hash with
    | None ->
       let table = Hashtbl.create 100 in
       filter_ip_hash := Some table;
       table
    | Some table -> table
  in
  let f = open_in filename in
  try
    while true do
      let line = input_line f in
      Hashtbl.add h line ()
    done;
    ActionDone
  with End_of_file -> ActionDone


let options = [
  mkopt (Some 'h') "help" Usage "show this help";
  mkopt (Some 'v') "verbose" (Set verbose) "print more info to stderr";
  mkopt None "laxist" (TrivialFun X509Util.relax_x509_constraints) "relax some constraints on certificate parsing";
  mkopt None "maxlen" (IntFun (fun i -> maxlen := Some i; ActionDone)) "set the string max length";
  mkopt None "no-maxlen" (TrivialFun (fun () -> maxlen := None)) "reset the string max length";

  mkopt (Some '2') "ad2" (Set v2_answer_dump) "use the v2 answer_dump";
  mkopt (Some '1') "ad1" (Clear v2_answer_dump) "use the v1 answer_dump";

  mkopt (Some 'a') "all" (TrivialFun (fun () -> action := All)) "show all the information and records of an answer";
  mkopt (Some 'j') "json" (TrivialFun (fun () -> action := AllJson)) "show all the information and records of an answer (JSON)";
  mkopt (Some 'I') "ip" (TrivialFun (fun () -> action := IP)) "only show the IP of the answers";
  mkopt (Some 'D') "dump" (TrivialFun (fun () -> action := Dump)) "dumps the answers";
  mkopt (Some 's') "ciphersuite" (TrivialFun (fun () -> action := Suite; update_enrich_level 2)) "only show the ciphersuite chosen";
  mkopt (Some 'S') "ske" (TrivialFun (fun () -> action := SKE; update_enrich_level 2)) "only show information relative to ServerKeyExchange";
  mkopt None "server-random" (TrivialFun (fun () -> action := ServerRandom; update_enrich_level 2)) "only output the server random";
  mkopt None "scapy-style" (TrivialFun (fun () -> action := Scapy)) "outputs the records as independant scapy-style packets";
  mkopt None "output-pcap" (TrivialFun (fun () -> action := Pcap)) "export the answer as a PCAP";
  mkopt None "answer-type" (TrivialFun (fun () -> action := AnswerType; update_enrich_level 9)) "prints the answer types";
  mkopt None "record-types" (TrivialFun (fun () -> action := RecordTypes; update_enrich_level 2)) "prints the records received";
  mkopt None "junk-length" (IntVal junk_length) "Sets the max length of junk stuff to print";
  mkopt None "certificates" (StringFun (fun s -> action := SaveCertificates s; update_enrich_level 3; ActionDone)) "saves certificates";
  mkopt None "output-certificates" (TrivialFun (fun () -> action := OutputCerts; update_enrich_level 3)) "output certificates as hex strings";
  mkopt None "cn" (TrivialFun (fun () -> action := Subject; update_enrich_level 2)) "show the subect";
  mkopt None "http-names" (TrivialFun (fun () -> action := HTTPNames; update_enrich_level 5)) "prints the answer types";
  mkopt (Some 'g') "get" (StringFun do_get_action) "Walks through the answers using a get string";

  mkopt None "always-enrich" (TrivialFun (fun () -> enrich_style := AlwaysEnrich)) "always enrich the structure parsed";
  mkopt None "never-enrich" (TrivialFun (fun () -> enrich_style := NeverEnrich)) "never enrich the structure parsed";
  mkopt None "enrich-level" (IntFun set_enrich_level) "enrich the structure parsed up to a certain level";

  mkopt None "filter-ip" (StringVal filter_ip) "only print info regarding this ip";
  mkopt None "filter-ips" (StringFun load_filter_ips_from_file) "only print info regarding a set of ips";

  mkopt None "versionACSAC" (TrivialFun (fun () -> action := VersionACSAC; update_enrich_level 3)) "only show the version chosen (ACSAC-style)";
  mkopt None "ciphersuiteACSAC" (TrivialFun (fun () -> action := SuiteACSAC; update_enrich_level 3)) "only show the ciphersuite chosen (ACSAC-style)";
]



let rec get_one_of v = function
  | [] -> None
  | p::ps -> match get v p with
    | Right s -> Some s
    | Left _ -> get_one_of v ps

let maybe_print ip = function
  | None -> ()
  | Some s -> Printf.printf "%s: %s\n" ip s


let dump_extract s =
  let len2consider = min !junk_length (String.length s) in
  let s2consider = String.sub s 0 len2consider in
  let hex_s = hexdump s2consider in
  let printable_buf = Buffer.create len2consider in
  for i = 0 to len2consider - 1 do
    let c = int_of_char s2consider.[i] in
    if c < 32 || c > 126
    then Buffer.add_char printable_buf '.'
    else Buffer.add_char printable_buf s2consider.[i]
  done;
  Printf.sprintf "%s (%s)" hex_s (Buffer.contents printable_buf)


let handle_answer answer =
  let ip = string_of_v2_ip answer.ip_addr in
  let this_one, again =
    match !filter_ip, !filter_ip_hash with
    | "", None -> true, true
    | _, Some table -> Hashtbl.mem table ip, true
    | _, _ -> let ok = !filter_ip = ip in ok, not ok
  in
  if this_one then begin
    (* TODO: Take care that an empty answer is correctly signaled! *)
    match !action with
      | IP -> print_endline ip
      | Dump -> print_string (exact_dump_answer_dump_v2 answer)
      | All ->
        print_endline ip;
	let opts = { default_output_options with oo_verbose = !verbose; indent = "  " ; maxlen = !maxlen } in
	begin
          match parse_all_tls_records !enrich_style !verbose answer with
	  | [], _, None -> ()
	  | [], _, Some _ ->
            let records, _, error = parse_all_ssl2_records !enrich_style !verbose answer in
            List.iter (fun r -> print_endline (print_value ~options:opts (value_of_ssl2_record r))) records;
            if error then print_endline "  ERROR"
	  | records, _, rem ->
            List.iter (fun r -> print_endline (print_value ~options:opts (value_of_tls_record r))) records;
	    match rem, !verbose with
	    | None, _ -> ()
	    | Some _, false -> print_endline "  ERROR"
	    | Some s, true -> print_endline ("  ERROR (Remaining: " ^ (hexdump s) ^ ")")
        end
      | AllJson ->
	let opts = { default_output_options with oo_verbose = !verbose; indent = "  " ; maxlen = !maxlen } in
	begin
          match parse_all_tls_records !enrich_style !verbose answer with
	  | [], _, None -> ()
	  | [], _, Some _ ->
             let records, _, error = parse_all_ssl2_records !enrich_style !verbose answer in
             let record_values = VList [VString (ip, false); VBool error; VList (List.map (fun r -> value_of_ssl2_record r) records)] in
             print_endline (Json.json_of_value ~options:opts record_values);
	  | records, _, rem ->
             let record_values = VList [VString (ip, false); VBool (rem != None); VList (List.map (fun r -> value_of_tls_record r) records)] in
             print_endline (Json.json_of_value ~options:opts record_values);
        end
      | Suite ->
        let _, ctx, _ = parse_all_tls_records !enrich_style !verbose answer in
	begin
	  match ctx.future.proposed_ciphersuites with
	  | [cs] -> Printf.printf "%s: %s\n" ip (string_of_ciphersuite cs)
	  | _ -> if !verbose then Printf.printf "%s: ERROR" ip
        end
      | SKE ->
        let ctx =
          try let _, ctx, _ = parse_all_tls_records !enrich_style !verbose answer in ctx
          with _ -> empty_context (Tls.default_prefs DummyRNG)
        in
        begin
          let subject_hash = match ctx.future.f_certificates with
            | (Parsed (_, { tbsCertificate = { issuer_raw = Some s } }))::_ -> hexdump (CryptoUtil.sha1sum s)
            | _ -> "NO-CERT-PARSED"
          in
          match ctx.future.f_server_key_exchange with
          | SKE_DHE { params = params } ->
            Printf.printf "%s: DHE,%s,%s,%s,%s\n" ip subject_hash (hexdump params.dh_p)
              (hexdump params.dh_g) (hexdump params.dh_Ys)

          | SKE_ECDHE { ecdhe_params = { ecdh_type = ECCT_NamedCurve;
                                         ecdh_params = ECP_NamedCurve curve;
                                         ecdh_public = point} } ->
            Printf.printf "%s: ECDHE,%s,%s,%s\n" ip subject_hash
              (string_of_ec_named_curve curve) (hexdump point)

          | SKE_ECDHE _ -> if !verbose then Printf.printf "%s: Non-named curve in ECDHE\n" ip
          | Unparsed_SKEContent "" -> if !verbose then Printf.printf "%s: NO_SKE\n" ip
          | _ -> if !verbose then Printf.printf "%s: NOT PARSED YET\n" ip
        end
      | ServerRandom ->
        let _, ctx, _ = parse_all_tls_records !enrich_style !verbose answer in
	begin
	  match ctx.future.f_server_random with
	  | "" -> if !verbose then Printf.printf "%s: ERROR" ip
	  | r -> Printf.printf "%s: %s\n" ip (hexdump r)
        end
      | Scapy ->
        let records, _, _ = parse_all_tls_records !enrich_style !verbose answer in
        let rec convert_to_scapy (len, ps) = function
          | [] -> List.rev ps
          | r::rs ->
            let dump = exact_dump_tls_record r in
            let new_p =
              Printf.sprintf "IP(src=\"%s\")/TCP(sport=%d,dport=12345,seq=%d,flags=\"\")/(\"%s\".decode(\"hex\"))"
                ip answer.port len (hexdump dump)
            in
            convert_to_scapy (len + (String.length dump), new_p::ps) rs
        in
        Printf.printf "ps = [%s]\n" (String.concat ",\n  " (convert_to_scapy (0, []) records))
      | Pcap ->
        let records, _, _ = parse_all_tls_records !enrich_style !verbose answer in
        let rec convert_to_pcap len ps = function
          | [] -> ()
          | r::rs ->
            let dump = exact_dump_tls_record r in
	    let ip = match answer.ip_addr with AD_IPv4 ipv4 -> ipv4 | _ -> String.make 4 '\x00' in
            let new_p = Pcap.mk_packet ip answer.port dump len in
            print_string (Parsifal.exact_dump Pcap.dump_packet new_p);
            convert_to_pcap (len + (String.length dump)) (new_p::ps) rs
        in
        convert_to_pcap 0 [] records
      | AnswerType ->
         begin
           match (parse_answer !enrich_style !verbose answer).pa_content with
           | Empty ->
              Printf.printf "%s\tE\n" ip

           | TLSAlert (_, al, at) ->
              Printf.printf "%s\tA\t%s\t%s\n" ip (string_of_tls_alert_level al) (string_of_tls_alert_type at)
           | SSLv2Alert e ->
              Printf.printf "%s\tA\tSSLv2_ALERT\t%s\n" ip (string_of_ssl2_error e)

           | TLSHandshake {sh_version = v; sh_ciphersuite = c; server_certificates = (Parsed (_, cert))::_} ->
              let s = String.concat "" (List.map string_of_atv (List.flatten cert.tbsCertificate.subject)) in
              Printf.printf "%s\tH\t%s\t%s\t%s\n" ip (string_of_tls_version v) (string_of_ciphersuite c) (quote_string s)
           | SSLv2Handshake {ssl2_version = v; cipher_specs = cs; certificate = Parsed (_, cert)} ->
              let s = String.concat "" (List.map string_of_atv (List.flatten cert.tbsCertificate.subject))
              and cs_str = String.concat "," (List.map (fun c -> string_of_value (value_of_ssl2_cipher_spec c)) cs) in
              Printf.printf "%s\tH\t%s\t%s\t%s\n" ip (string_of_tls_version v) cs_str (quote_string s)

           | TLSHandshake {sh_version = v; sh_ciphersuite = c} ->
              Printf.printf "%s\tH\t%s\t%s\tNoCertParsed\n" ip (string_of_tls_version v) (string_of_ciphersuite c)
           | SSLv2Handshake {ssl2_version = v; cipher_specs = cs} ->
              let cs_str = String.concat "," (List.map (fun c -> string_of_value (value_of_ssl2_cipher_spec c)) cs) in
              Printf.printf "%s\tH\t%s\t%s\tNoCertParsed\n" ip (string_of_tls_version v) cs_str

           | Junk ("", s) -> Printf.printf "%s\tJ\t%s\n" ip (dump_extract s)
           | Junk (s, _) -> Printf.printf "%s\tJ\t%s\n" ip s
         end
      | RecordTypes ->
        let records, _, err = parse_all_tls_records !enrich_style !verbose answer in
        let rec get_type = function
          | [], false -> []
          | [], true -> ["ERROR"]
          | { content_type = CT_Alert; record_content = Alert a }::r, err ->
            let al = int_of_tls_alert_level a.alert_level
            and at = int_of_tls_alert_type  a.alert_type in
            (Printf.sprintf "Alert(%d,%d)" al at)::(get_type (r, err))
          | { content_type = CT_Handshake ; record_content = Handshake h }::r, err ->
            (string_of_hs_message_type h.handshake_type)::(get_type (r, err))
          | _::r, err -> "UNKNOWN"::(get_type (r, err))
        in
        let res = String.concat " " (get_type (records, err <> None)) in
        Printf.printf "%s\t%s\n" ip res
      | Subject ->
         let subject = match (parse_answer !enrich_style !verbose answer).pa_content with
           | TLSHandshake {server_certificates = (Parsed (_, cert))::_}
           | SSLv2Handshake {certificate = Parsed (_, cert)} ->
              Some (String.concat "" (List.map string_of_atv (List.flatten cert.tbsCertificate.subject)))
           | _ -> None
         in
         begin
           match subject with
           | None -> ()
           | Some subject -> Printf.printf "%s: %s\n" ip subject
         end;
      | Get ->
        let records, _ = parse_records_as_values !enrich_style !verbose answer in
        let get_one_path p = 
          match get (VList records) p with
          | Left err -> if !verbose then prerr_endline (ip ^ ": " ^ err); []
          | Right s -> [s]
        in
        let results = List.flatten (List.map get_one_path !path) in
        if results <> [] then Printf.printf "%s: %s\n" ip (String.concat ", " results)


      | SuiteACSAC ->
         begin
           match (parse_answer !enrich_style !verbose answer).pa_content with
           | TLSHandshake {sh_ciphersuite = c} ->
              Printf.printf "%s: %s\n" ip (string_of_ciphersuite c)
           | SSLv2Handshake {cipher_specs = c::_} ->
              Printf.printf "%s: %s\n" ip (string_of_value (value_of_ssl2_cipher_spec c))
           | _ -> ()
         end
      | VersionACSAC ->
	begin
	  match parse_records_as_values !enrich_style !verbose answer with
	  | r::_, _ ->
	    let result = get_one_of r ["record_content.handshake_content.server_version";
				       "record_content.ssl2_handshake_content.ssl2_server_version";
				       "record_version"] in
	    maybe_print ip result
	  | _ -> ()
	end

      | SaveCertificates dir ->
         let rec save_cert i = function
	   | [] -> i
	   | c::cs ->
	      (* TODO: save the file as dir/by-hash/HASH and add a hard link *)
	      let s = exact_dump (dump_trivial_union dump_certificate) c in
	      let f = open_out (dir ^ "/" ^ ip ^ "-" ^ (string_of_int i)) in
	      output_string f s;
	      close_out f;
	      save_cert (i+1) cs
	 in
         let n_saved =
           match (parse_answer !enrich_style !verbose answer).pa_content with
           | TLSHandshake h -> save_cert 0 h.server_certificates
           | SSLv2Handshake h -> save_cert 0 [h.certificate]
           | _ -> 0
         in
	 Printf.printf "%s: %d certificate(s) saved.\n" ip n_saved

      | OutputCerts ->
         let certs =
           match (parse_answer !enrich_style !verbose answer).pa_content with
           | TLSHandshake h -> h.server_certificates
           | SSLv2Handshake h -> [h.certificate]
           | _ -> []
         in
         List.iter (fun c -> print_endline (hexdump (exact_dump (dump_trivial_union dump_certificate) c))) certs

      | HTTPNames ->
         let cert = match (parse_answer !enrich_style !verbose answer).pa_content with
           | TLSHandshake {server_certificates = (Parsed (_,cert))::_}
           | SSLv2Handshake {certificate = Parsed (_, cert)} -> Some cert
           | _ -> None
         in
	 begin
	   match cert with
	   | Some c ->
	      let https_dns_and_ips = extract_dns_and_ips c in
	      let string_of_dns_or_ip (t, v) = t ^ "=" ^ (quote_string v) in
	      Printf.printf "%s: %s\n" ip (String.concat ", " (List.map string_of_dns_or_ip https_dns_and_ips))
	   | None -> ()
	 end
  end;
  again

let parse_answer_from_v1 input = v2_of_v1 (parse_answer_dump input)
let parse_answer_from_v2 = parse_answer_dump_v2

let real_parse_answer_dump = ref parse_answer_from_v1

let rec handle_one_file input =
  let finalize_ok answer =
    if handle_answer answer then handle_one_file input else return ()
  and finalize_nok = function
    | (ParsingException _) as e ->
      if input.lwt_eof && (input.string_input.cur_length = 0)
      then return ()
      else fail e
    | e -> fail e
  in try_bind (fun () -> lwt_parse_wrapper !real_parse_answer_dump input) finalize_ok finalize_nok


let _ =
  TlsDatabase.enrich_suite_hash ();
  try
    let args = parse_args ~progname:"test_answerDump" options Sys.argv in
    if !v2_answer_dump then real_parse_answer_dump := parse_answer_from_v2;
    if !action = Pcap
    then print_string (Pcap.std_pcap_hdr_str);
    let open_files = function
      | [] -> input_of_channel ~verbose:(!verbose) "(stdin)" Lwt_io.stdin >>= fun x -> return [x]
      | _ -> Lwt_list.map_s (fun fn -> input_of_filename fn) args
    in
    Lwt_main.run (open_files args >>= Lwt_list.iter_s handle_one_file);
  with
    | End_of_file -> ()
    | ParsingException (e, h) -> prerr_endline (string_of_exception e h); exit 1
    | e -> prerr_endline (Printexc.to_string e)

