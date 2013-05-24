open Parsifal
open BasePTypes
open PTypes
open Dns
open Getopt


type 'a quoted_printable_container = 'a

let parse_quoted_printable_container parse_fun input =
  let buf = Buffer.create 1024 in
  while not (eos input) do
    let c = parse_byte input in
    if c = int_of_char '='
    then begin
      let hibits = extract_4bits input in
      let lobits = extract_4bits input in
      Buffer.add_char buf (char_of_int ((hibits lsl 4) lor lobits))
    end else Buffer.add_char buf (char_of_int c)
  done;
  let content = Buffer.contents buf in
  let new_input = get_in_container input "quoted_printable_container" content in
  let res = parse_fun new_input in
  check_empty_input true new_input;
  res

let dump_quoted_printable_container _dump_fun _buf _o =
  raise (ParsingException (NotImplemented "dump_quoted_printable", []))

let value_of_quoted_printable_container = value_of_container



type action = All | Dig | AnswerOnly
let action = ref Dig
let verbose = ref false
let filter = ref ""

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



let options = [
  mkopt (Some 'h') "help" Usage "show this help";
  mkopt (Some 'v') "verbose" (Set verbose) "print more info to stderr";

  mkopt (Some 'A') "all" (TrivialFun (fun () -> action := All)) "show all the information of the answer";
  mkopt (Some 'D') "dig-style" (TrivialFun (fun () -> action := Dig)) "prints the answer like dig";
  mkopt (Some 'a') "answer-only" (TrivialFun (fun () -> action := AnswerOnly)) "only prints the answer RR";

  mkopt (Some 'f') "filter-ip" (StringVal filter) "filter on a given IP";

  mkopt None "always-enrich" (TrivialFun (fun () -> enrich_style := AlwaysEnrich)) "always enrich the structure parsed";
  mkopt None "never-enrich" (TrivialFun (fun () -> enrich_style := NeverEnrich)) "never enrich the structure parsed";
  mkopt None "enrich-level" (IntFun set_enrich_level) "enrich the structure parsed up to a certain level";
]



let display_question q =
  Printf.printf "%-30s         %-10s %-10s\n"
    (String.concat "." (string_of_domain q.qname))
    (string_of_rr_type q.qtype)
    (string_of_rr_class q.qclass)

let display_rr rr =
  Printf.printf "%-30s %-7d %-10s %-10s %s\n"
    (String.concat "." (string_of_domain rr.rname)) rr.ttl
    (string_of_rr_class rr.rclass)
    (string_of_rr_type rr.rtype)
    (string_of_value (value_of_rdata rr.rdata))

let display_dns_message msg =
  Printf.printf ";; id = %d\n" msg.id;
  Printf.printf ";; QR=%b Opcode=%s AA=%b TC=%b RD=%b RA=%b Z=%d RCODE=%s\n"
    msg.qr (string_of_opcode msg.opcode) msg.aa msg.tc msg.rd msg.ra msg.z (string_of_rcode msg.rcode);
  Printf.printf "\n;; QUESTION SECTION:\n";
  List.iter display_question msg.questions;
  Printf.printf "\n;; ANSWER SECTION:\n";
  List.iter display_rr msg.answers;
  Printf.printf "\n;; AUTHORITY SECTION:\n";
  List.iter display_rr msg.authority_answers;
  Printf.printf "\n;; ADDITIONAL SECTION:\n";
  List.iter display_rr msg.additional_records



let _ =
  let args = parse_args ~progname:"picodig" options Sys.argv in
  let f = match args with
    | [] -> stdin
    | [filename] -> open_in filename
    | _ -> usage "ic2012dns" options (Some "ic2012dns needs one or zero argument for the file to parse")
  in
  try
    while true do
      let ip = input_line f in
      let data = input_line f in
      if !filter = "" || !filter = ip then begin
        if String.length data > 0 then begin
          let input = input_of_string ip data in
          try
            let answer = parse_quoted_printable_container parse_dns_message input in
            match !action with
            | All -> print_endline (print_value ~name:ip ~indent:"  " (value_of_dns_message answer))
            | Dig ->
              print_endline ip;
              display_dns_message answer;
              print_newline ()
            | AnswerOnly -> match answer with
              | { qr = true;  qdcount = 1; ancount = 1; answers = [r] } ->
                Printf.printf "%-16s " ip;
                display_rr r
              | { qr = true; rcode = rcode; ancount = 0; answers = [] } ->
                if !verbose then Printf.printf "%-16s %s\n" ip (string_of_rcode rcode)
              | _ -> if !verbose then Printf.printf "%-16s more than one RR or invalid answer.\n" ip
          with
          | ParsingException (e, h) ->
            if !verbose then Printf.printf "%-16s ERROR (%s)\n" ip (string_of_exception e h)
        end else if !verbose then Printf.printf "%-16s EMPTY\n" ip
      end
    done
  with
  | End_of_file -> exit 0
  | ParsingException (e, h) -> prerr_endline (string_of_exception e h); exit 1
  | e -> prerr_endline (Printexc.to_string e); exit 1
