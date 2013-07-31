open Parsifal
open BasePTypes
open PTypes
open Getopt


(* TODO:
   - Improve ASN.1 display
   - Allow for multiple -g options
*)

let parser_type = ref "binstring"
type container = NoContainer | HexContainer | Base64Container | PcapTCPContainer of int | PcapUDPContainer of int
let container = ref NoContainer

let verbose = ref false
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
let path = ref ""

let type_list = ref false
let input_in_args = ref false
let multiple_values = ref false


let options = [
  mkopt (Some 'h') "help" Usage "show this help";
  mkopt (Some 'v') "verbose" (Set verbose) "print more info to stderr";

  mkopt (Some 'T') "type" (StringVal parser_type) "select the parser type";
  mkopt (Some 'L') "list-types" (Set type_list) "prints the list of supported types";

  mkopt (Some 'i') "input-args" (Set input_in_args) "consider args as data, not filenames";
  mkopt (Some 'm') "multiple-values" (Set multiple_values) "each argument is in fact a sequence of values to parse";

  mkopt (Some 'a') "all" (TrivialFun (fun () -> action := All)) "show all the information";
  mkopt (Some 'g') "get" (StringFun (fun s -> action := Get; path := s; ActionDone)) "select the info to extract";
  mkopt (Some 'j') "json" (TrivialFun (fun () -> action := JSon)) "represents the parsed value as a JSON";

  mkopt (Some 'B') "base64" (TrivialFun (fun () -> container := Base64Container)) "the data is first decoded as base64";
  mkopt (Some 'H') "hex" (TrivialFun (fun () -> container := HexContainer)) "the data is first decoded as hexa";
  mkopt None "pcap-tcp" (IntFun (fun p -> container := PcapTCPContainer p; ActionDone)) "the data is first extracted from a PCAP";
  mkopt None "pcap-udp" (IntFun (fun p -> container := PcapUDPContainer p; ActionDone)) "the data is first extracted from a PCAP";

  mkopt None "always-enrich" (TrivialFun (fun () -> enrich_style := AlwaysEnrich)) "always enrich the structure parsed";
  mkopt None "never-enrich" (TrivialFun (fun () -> enrich_style := NeverEnrich)) "never enrich the structure parsed";
  mkopt None "enrich-level" (IntFun set_enrich_level) "enrich the structure parsed up to a certain level";
]


let parse_tls_records_as_value i =
  let recs, _, _ = TlsUtil.parse_all_records (!verbose) i in
  VList (List.map Tls.value_of_tls_record recs)


let type_handlers : (string, string_input -> value) Hashtbl.t = Hashtbl.create 10

let _ =
  Hashtbl.add type_handlers "string" (fun i -> value_of_string (parse_rem_string i));
  Hashtbl.add type_handlers "binstring" (fun i -> value_of_binstring (parse_rem_string i));
  Hashtbl.add type_handlers "x509" (fun i -> X509.value_of_certificate (X509.parse_certificate i));
  Hashtbl.add type_handlers "asn1" (fun i -> Asn1PTypes.value_of_der_object (Asn1PTypes.parse_der_object i));
  Hashtbl.add type_handlers "png" (fun i -> Png.value_of_png_file (Png.parse_png_file i));
  Hashtbl.add type_handlers "pe" (fun i -> Pe.value_of_pe_file (Pe.parse_pe_file i));
  Hashtbl.add type_handlers "tar" (fun i -> Tar.value_of_tar_file (Tar.parse_tar_file i));
  Hashtbl.add type_handlers "answer_dump" (fun i -> AnswerDump.value_of_answer_dump (AnswerDump.parse_answer_dump i));
  Hashtbl.add type_handlers "tls_record" parse_tls_records_as_value;
  Hashtbl.add type_handlers "dns" (fun i -> Dns.value_of_dns_message (Dns.parse_dns_message i));
  Hashtbl.add type_handlers "pcap" (fun i -> Pcap.value_of_pcap_file (Pcap.parse_pcap_file i));
  ()



let show_type_list error =
  print_endline "The types available are:";
  Hashtbl.iter (fun t -> fun _ -> print_string "  "; print_endline t) type_handlers;
  usage "perceval" options error


let mk_parse_value () =
  let parse_fun =
    try
      let raw_parse_fun = Hashtbl.find type_handlers !parser_type in
      match !container with
	| NoContainer -> raw_parse_fun
	| HexContainer -> parse_hex_container raw_parse_fun
	| Base64Container -> Base64.parse_base64_container Base64.AnyHeader raw_parse_fun
	| PcapTCPContainer port -> fun i -> VList (PcapContainers.parse_tcp_container port raw_parse_fun i)
	| PcapUDPContainer port -> fun i -> VList (PcapContainers.parse_udp_container port raw_parse_fun i)
    with
      Not_found -> show_type_list (Some "parser type not found.")
  in fun input ->
    let v = parse_fun input in
    match !action with
    | All -> print_endline (print_value ~verbose:!verbose v)
    | JSon -> print_endline (Json.json_of_value ~verbose:!verbose v)
    | Get ->
      match get v !path with
      | Left err -> if !verbose then prerr_endline err
      | Right s -> print_endline s


let handle_stdin () = failwith "Not implemented"
let handle_filename filename = string_input_of_filename ~verbose:(!verbose) ~enrich:(!enrich_style) filename
let handle_inline data = input_of_string ~verbose:!verbose ~enrich:!enrich_style "(inline)" data


let _ =
  try
    let args = parse_args ~progname:"perceval" options Sys.argv in
    let parse_value = mk_parse_value () in
    if !type_list then show_type_list None;  
    begin
      match args with
      | [] -> handle_stdin ()
      | l ->
	let f =
	  if !input_in_args
	  then handle_inline
	  else handle_filename
	in
	let handle_one_input s =
	  let input = f s in
	  parse_value input;
	  while (!multiple_values) && not (eos input) do
	    parse_value input
	  done;
	in
	List.iter handle_one_input l
    end;
    exit 0
  with
    | ParsingException (e, h) -> prerr_endline (string_of_exception e h); exit 1
    | e -> prerr_endline (Printexc.to_string e); exit 1
