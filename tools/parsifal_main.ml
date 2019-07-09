open Parsifal
open BasePTypes
open PTypes
open Getopt


(* TODO:
   - Improve ASN.1 display
   - Allow for multiple -g options
*)

let parser_type = ref "binstring"
type container =
  | NoContainer
  | HexContainer
  | Base64Container
  | GZipContainer
  | PcapTCPContainer of int
  | PcapUDPContainer of int
  | PcapTLSContainer of int
let container = ref NoContainer
let port = ref 80

let keylogfile = ref ""

let verbose = ref false
let maxlen = ref (Some 70)
let no_alias = ref false

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

type action = All | Get | JSon
let action = ref All
let path = ref []

let do_get_action path_str =
  action := Get;
  path := (!path)@[path_str];
  ActionDone

let type_list = ref false
let input_in_args = ref false
let multiple_values = ref false


let load_kerb_rsa_key filename =
  try
    Padata.rsa_key := Pkcs1.load_rsa_private_key filename;
    ActionDone
  with _ -> ShowUsage (Some "Please supply a valid DER-encoded RSA key.")

let load_aes_ticket_key filename =
  try
    Padata.aes_ticket_key := Some (get_file_content filename);
    ActionDone
  with _ -> ShowUsage (Some "Please supply a valid AES key.")


(* TODO: Move this? *)
let mk_known_secrets ms_only filename =
  let rec read_line accu f =
    let l_opt =
      try Some (input_line f)
      with End_of_file -> None
    in
    match l_opt with
    | None -> List.rev accu
    | Some l ->
      match string_split ' ' l with
      | ["RSA"; enc_pms; clr_pms] ->
         (* TODO: Handle hexparse exceptions *)
         let new_accu = if ms_only then accu else
            (Tls.RSA_PMS (hexparse enc_pms, hexparse clr_pms))::accu in
        read_line new_accu f
      | ["CLIENT_RANDOM"; cr; clr_ms] ->
         (* TODO: Handle hexparse exceptions *)
         let new_accu = (Tls.MS (hexparse cr, hexparse clr_ms))::accu in
         read_line new_accu f
      | _ -> read_line accu f
  in
  if filename = ""  then [] else begin
    let f = open_in filename in
    read_line [] f
  end

let ctx = ref (Tls.empty_context (Tls.default_prefs Tls.DummyRNG))
let init_ctx () =
  let secrets = mk_known_secrets false !keylogfile in
  let prefs = { (Tls.default_prefs Tls.DummyRNG) with Tls.known_master_secrets = secrets } in
  ctx := Tls.empty_context prefs


let options = [
  mkopt (Some 'h') "help" Usage "show this help";
  mkopt (Some 'v') "verbose" (Set verbose) "print more info to stderr";
  mkopt None "laxist" (TrivialFun X509Util.relax_x509_constraints) "relax some constraints on certificate parsing";
  mkopt None "maxlen" (IntFun (fun i -> maxlen := Some i; ActionDone)) "set the string max length";
  mkopt None "no-maxlen" (TrivialFun (fun () -> maxlen := None)) "reset the string max length";
  mkopt None "no-alias" (Set no_alias) "remove alias structure from output";
  mkopt (Some 'p') "port" (IntVal port) "set the port to pcap parsers";

  mkopt (Some 'T') "type" (StringVal parser_type) "select the parser type";
  mkopt (Some 'L') "list-types" (Set type_list) "prints the list of supported types";

  mkopt (Some 'i') "input-args" (Set input_in_args) "consider args as data, not filenames";
  mkopt (Some 'm') "multiple-values" (Set multiple_values) "each argument is in fact a sequence of values to parse";

  mkopt (Some 'a') "all" (TrivialFun (fun () -> action := All)) "show all the information";
  mkopt (Some 'g') "get" (StringFun do_get_action) "select the info to extract";
  mkopt (Some 'j') "json" (TrivialFun (fun () -> action := JSon)) "represents the parsed value as a JSON";

  mkopt (Some 'B') "base64" (TrivialFun (fun () -> container := Base64Container)) "the data is first decoded as base64";
  mkopt (Some 'H') "hex" (TrivialFun (fun () -> container := HexContainer)) "the data is first decoded as hexa";
  mkopt (Some 'G') "gzip" (TrivialFun (fun () -> container := GZipContainer)) "the data is first GZIP uncompressed"; 
  mkopt None "pcap-tcp" (IntFun (fun p -> container := PcapTCPContainer p; ActionDone)) "the data is first extracted from a PCAP";
  mkopt None "pcap-udp" (IntFun (fun p -> container := PcapUDPContainer p; ActionDone)) "the data is first extracted from a PCAP";
  mkopt None "pcap-tls" (IntFun (fun p -> container := PcapTLSContainer p; ActionDone)) "the data is first extracted from a PCAP and TLS messages";
  mkopt None "keylogfile" (StringVal keylogfile) "defines the files where the TLS secrets are stored";

  mkopt None "always-enrich" (TrivialFun (fun () -> enrich_style := AlwaysEnrich)) "always enrich the structure parsed";
  mkopt None "never-enrich" (TrivialFun (fun () -> enrich_style := NeverEnrich)) "never enrich the structure parsed";
  mkopt None "enrich-level" (IntFun set_enrich_level) "enrich the structure parsed up to a certain level";

  mkopt None "kerberos-rsa-key" (StringFun load_kerb_rsa_key) "set the RSA key to decrypt Kerberos PKINIT messages";
  mkopt None "kerberos-aes-key" (StringFun load_aes_ticket_key) "set the AES key to decrypt Kerberos ticket";
]


let parse_tls_records_as_value ctx dir i =
  match TlsEngineNG.parse_all_records dir (Some !ctx) i with
  | [], None -> VUnit
  | [], Some _ ->
    begin
      i.cur_offset <- 0;
      match try_parse (Ssl2.parse_ssl2_record { Ssl2.cleartext = true }) i with
      | None -> VError "No SSLv2 nor TLS message could be parsed"
      | Some first ->
	let next, _ = TlsEngineNG.parse_all_records dir (Some !ctx) i in
	let values = (Ssl2.value_of_ssl2_record first)::(List.map Tls.value_of_tls_record next) in
	VList values
    end
  | recs, _ ->
    VList (List.map Tls.value_of_tls_record recs)

let parse_bundled_certificate i =
  parse_varlen_container parse_uint32 "varlen_container" X509.parse_certificate i

let parse_tls_container port parse_fun input =
  let parse_tls_aux ctx dir i =
    let res, _ = TlsEngineNG.parse_all_records dir (Some !ctx) i in
    res
  in

  (* TODO: Handle properly unparsed AppData! *)
  let rec extract_appdata accu cur_appdata cur_dir = function
    | [] -> List.rev ((cur_dir, Buffer.contents cur_appdata)::accu)
    | ((dir, { Tls.record_content = Tls.ApplicationData appdata })::rs) as rlist ->
      if dir = cur_dir then begin
	Buffer.add_string cur_appdata appdata;
	extract_appdata accu cur_appdata cur_dir rs
      end else begin
	let new_accu = (cur_dir, Buffer.contents cur_appdata)::accu in
	extract_appdata new_accu (Buffer.create 1024) dir rlist
      end
    | _::rs -> extract_appdata accu cur_appdata cur_dir rs
  in

  let handle_connection enrich (k, oriented_recs) =
    let rec merge = function
      | [] -> []
      | (_, [])::ls -> merge ls
      | (dir, r::rs)::ls -> (dir, r)::(merge ((dir, rs)::ls))
    in
    let c2s = Printf.sprintf "%s:%d -> %s:%d\n"
      (string_of_ipv4 (fst k.PcapContainers.source)) (snd k.PcapContainers.source)
      (string_of_ipv4 (fst k.PcapContainers.destination)) (snd k.PcapContainers.destination)
    and s2c = Printf.sprintf "%s:%d -> %s:%d\n"
      (string_of_ipv4 (fst k.PcapContainers.destination)) (snd k.PcapContainers.destination)
      (string_of_ipv4 (fst k.PcapContainers.source)) (snd k.PcapContainers.source) in
    let str_of_dir = function ClientToServer -> c2s | ServerToClient -> s2c in
    let parse_as_value (dir, appdata) =
      let i = input_of_string ~enrich:(enrich) (str_of_dir dir) appdata in
      parse_fun i
    in
    match extract_appdata [] (Buffer.create 1024) ClientToServer (merge oriented_recs) with
    | [ClientToServer, ""] -> VUnit
    | oriented_appdata -> VList (List.map parse_as_value oriented_appdata)
  in

  let enrich = input.enrich in
  input.enrich <- AlwaysEnrich;
  let conns = PcapContainers.parse_oriented_tcp_container init_ctx port "HTTPS" (parse_tls_aux ctx) input in
  VList (List.map (handle_connection enrich) conns)



let type_handlers : (string, string * (string_input -> value)) Hashtbl.t = Hashtbl.create 10

let _ =
  Hashtbl.add type_handlers "string" ("String", fun i -> value_of_string (parse_rem_string i));
  Hashtbl.add type_handlers "binstring" ("Binary string", fun i -> value_of_binstring (parse_rem_string i));
  Hashtbl.add type_handlers "asn1" ("ASN.1", fun i -> Asn1PTypes.value_of_der_object (Asn1PTypes.parse_der_object i));
  Hashtbl.add type_handlers "x509" ("X509 certificate", fun i -> X509.value_of_certificate (X509.parse_certificate i));
  Hashtbl.add type_handlers "x509-bundle" ("Bundled X509 certificate", fun i -> X509.value_of_certificate (parse_bundled_certificate i));
  Hashtbl.add type_handlers "crl" ("X509 CRL", fun i -> Crl.value_of_certificateList (Crl.parse_certificateList i));
  Hashtbl.add type_handlers "png" ("PNG image", fun i -> Png.value_of_png_file (Png.parse_png_file i));
  Hashtbl.add type_handlers "pe" ("PE executable", fun i -> Pe.value_of_pe_file (Pe.parse_pe_file i));
  Hashtbl.add type_handlers "tar" ("TAR archive", fun i -> Tar.value_of_tar_file (Tar.parse_tar_file i));
  Hashtbl.add type_handlers "answer-dump-v1" ("Answer dump v1", fun i -> AnswerDump.value_of_answer_dump (AnswerDump.parse_answer_dump i));
  Hashtbl.add type_handlers "answer-dump" ("Answer dump v2", fun i -> AnswerDump.value_of_answer_dump_v2 (AnswerDump.parse_answer_dump_v2 i));
  Hashtbl.add type_handlers "tls" ("SSL/TLS record", parse_tls_records_as_value ctx ServerToClient);
  Hashtbl.add type_handlers "sslv2" ("SSLv2 record", fun i -> Ssl2.value_of_ssl2_record (Ssl2.parse_ssl2_record { Ssl2.cleartext = true } i));
  Hashtbl.add type_handlers "pcap-tls" ("PCAP containing TLS messages",
    fun i -> PcapContainers.value_of_oriented_tcp_container (fun x -> x)
      (PcapContainers.parse_oriented_tcp_container init_ctx !port "HTTPS" (parse_tls_records_as_value ctx) i));
  Hashtbl.add type_handlers "dns" ("DNS message", fun i -> Dns.value_of_dns_message (Dns.parse_dns_message i));
  Hashtbl.add type_handlers "pcap" ("PCAP capture file", fun i -> Pcap.value_of_pcap_file (Pcap.parse_pcap_file i));
  Hashtbl.add type_handlers "dvi" ("DVI file", fun i -> Dvi.value_of_dvi_file (Dvi.parse_dvi_file i));
  Hashtbl.add type_handlers "gzip" ("GZip compressed file", fun i -> ZLib.value_of_gzip_member (ZLib.parse_gzip_member i));
  Hashtbl.add type_handlers "fv" ("UEFI volume", fun i -> Uefi_fv.value_of_fv_volume (Uefi_fv.parse_fv_volume i));
  Hashtbl.add type_handlers "mrt" ("MRT archive", fun i -> Mrt.value_of_mrt_message (Mrt.parse_mrt_message i));
  Hashtbl.add type_handlers "rsa" ("PKCS#1 RSA key", fun i -> Pkcs1.value_of_rsa_private_key (Pkcs1.parse_rsa_private_key i));
  Hashtbl.add type_handlers "keytab" ("Kerberos keytab", fun i -> Keytab.value_of_keytab_file (Keytab.parse_keytab_file i));
  Hashtbl.add type_handlers "kerb-pkcs7" ("Kerberos PKCS#7", fun i -> Padata.value_of_kerb_pkcs7 (Padata.parse_kerb_pkcs7 i));
  Hashtbl.add type_handlers "kerberos-tcp" ("Kerberos TCP message", fun i -> Kerby.value_of_kerberos_msg (Kerby.parse_kerberos_msg i));
  Hashtbl.add type_handlers "kerberos-udp" ("Kerberos UDP message", fun i -> Kerby.value_of_kerberos_udp_msg (Kerby.parse_kerberos_udp_msg i));
  Hashtbl.add type_handlers "pac" ("PAC", fun i -> Pac.value_of_ad_win2k_pac (Pac.parse_ad_win2k_pac i));
  Hashtbl.add type_handlers "http" ("HTTP message", fun i -> Http.value_of_http_message (Http.parse_http_message None i));
  Hashtbl.add type_handlers "pcap-http" ("PCAP containing HTTP messages",
    fun i -> PcapContainers.value_of_oriented_tcp_container (fun x -> x)
      (PcapContainers.parse_oriented_tcp_container (fun () -> ()) !port "HTTP"
	 (fun dir -> fun i -> Http.value_of_http_message (Http.parse_http_message (Some dir) i)) i));
  Hashtbl.add type_handlers "ntp" ("NTP packets", fun i -> Libntp.value_of_ntp_packet (Libntp.parse_ntp_packet i));
  Hashtbl.add type_handlers "openpgp" ("OpenPGP message",
    fun i -> Libpgp.value_of_openpgp_message (Libpgp.parse_openpgp_message i));
  Hashtbl.add type_handlers "armored-openpgp" ("Armored OpenPGP message",
    fun i -> Libpgp.value_of_armored_openpgp_message (Libpgp.parse_armored_openpgp_message i));
  ()


let show_type_list () =
  let type_list = List.sort compare (Hashtbl.fold (fun t -> fun (desc, _) -> fun l -> (t,desc)::l) type_handlers []) in
  let maxlen = List.fold_left (fun accu -> fun (n, _) -> max (String.length n) accu) 0 type_list in
  let print_type max (n, d) =
    if !verbose
    then Printf.printf "%-*s %s\n" max n d
    else print_endline (n ^ ":" ^ d)
  in
  List.iter (print_type (maxlen + 2)) type_list

let mk_parse_value () =
  let parse_fun =
    try
      let _, raw_parse_fun = Hashtbl.find type_handlers !parser_type in
      match !container with
	| NoContainer -> raw_parse_fun
	| HexContainer -> parse_hex_container "hex_container" raw_parse_fun
	| Base64Container -> Base64.parse_base64_container Base64.AnyHeader "base64_container" raw_parse_fun
	| GZipContainer -> ZLib.parse_gzip_container "gzip:" raw_parse_fun
	| PcapTCPContainer port -> fun i ->
	  PcapContainers.value_of_tcp_container (fun x -> x)
	    (PcapContainers.parse_tcp_container port "tcp_container" raw_parse_fun i)
	| PcapUDPContainer port -> fun i ->
	  PcapContainers.value_of_udp_container (fun x -> x)
	    (PcapContainers.parse_udp_container port "udp_container" raw_parse_fun i)
	| PcapTLSContainer port -> parse_tls_container port raw_parse_fun
    with
      Not_found -> usage "parsifal" options (Some "Unknown parser type (try -L).")
  in fun input ->
    let opts = {
      default_output_options with
	oo_verbose = !verbose;
	maxlen = !maxlen;
	unfold_aliases = not !no_alias;
        eol = if !multiple_values then " " else "\n";
        indent_increment = if !multiple_values then "" else "  ";
    } in
    let v = parse_fun input in
    match !action with
    | All -> print_endline (print_value ~options:opts v)
    | JSon -> print_endline (Json.json_of_value ~options:opts v)
    | Get ->
      let get_one_path p =
        match get v p with
        | Left err -> if !verbose then prerr_endline err; []
        | Right s -> [s]
      in
      let results = List.flatten (List.map get_one_path !path) in
      if results <> [] then print_endline (String.concat ", " results)


let handle_stdin _ = string_input_of_stdin ~verbose:(!verbose) ~enrich:(!enrich_style) ()
let handle_filename filename = string_input_of_filename ~verbose:(!verbose) ~enrich:(!enrich_style) filename
let handle_inline data = input_of_string ~verbose:!verbose ~enrich:!enrich_style "(inline)" data


let _ =
  TlsDatabase.enrich_suite_hash ();
  try
    let args = parse_args ~progname:"perceval" options Sys.argv in
    let parse_value = mk_parse_value () in
    if !type_list then begin
      show_type_list ();
      exit 0;
    end;
    begin
      let handle_fun, real_args = match args with
      | [] -> handle_stdin, [""]
      | l ->
	let f =
	  if !input_in_args
	  then handle_inline
	  else handle_filename
	in f, l
      in	
      let handle_one_input s =
	let input = handle_fun s in
	parse_value input;
	while (!multiple_values) && not (eos input) do
	  parse_value input
	done;
      in
      List.iter handle_one_input real_args
    end;
    exit 0
  with
    | ParsingException (e, h) -> prerr_endline (string_of_exception e h); exit 1
    | e -> prerr_endline (Printexc.to_string e); exit 1
