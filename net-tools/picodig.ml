open Parsifal
open Dns
open Getopt

type action = All | Dig
let action = ref Dig
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


let query_type = ref RRT_A
let query_class = ref RRC_IN
let handle_type s = query_type := rr_type_of_string s; ActionDone
let handle_class s = query_class := rr_class_of_string s; ActionDone
let host = ref "8.8.8.8"



let options = [
  mkopt (Some 'h') "help" Usage "show this help";
  mkopt (Some 'v') "verbose" (Set verbose) "print more info to stderr";

  mkopt (Some 'A') "all" (TrivialFun (fun () -> action := All)) "show all the information of the answer";
  mkopt (Some 'D') "dig-style" (TrivialFun (fun () -> action := Dig)) "prints the answer like dig";

  mkopt None "always-enrich" (TrivialFun (fun () -> enrich_style := AlwaysEnrich)) "always enrich the structure parsed";
  mkopt None "never-enrich" (TrivialFun (fun () -> enrich_style := NeverEnrich)) "never enrich the structure parsed";
  mkopt None "enrich-level" (IntFun set_enrich_level) "enrich the structure parsed up to a certain level";

  mkopt (Some 't') "query-type" (StringFun handle_type) "sets the query type sent";
  mkopt (Some 'c') "query-class" (StringFun handle_class) "sets the query class sent";
  mkopt (Some 'H') "dns-server" (StringVal host) "sets the server to send the query to";
]


let mk_query name qtype qclass =
  let rec domain_of_stringlist = function
    | [] -> DomainEnd
    | l::r -> DomainLabel (l, domain_of_stringlist r)
  in
  let domain = domain_of_stringlist (string_split '.' name) in
  {
    id = 1234;
    unparsedStuff = 0x0100;
    qdcount = 1;
    ancount = 0; nscount = 0; arcount = 0;
    questions = [{qname = domain; qtype = qtype; qclass = qclass}];
    answers = []; authority_answers = []; additional_records = [];
  }


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
  Printf.printf ";; unparsedStuff = %d\n" msg.unparsedStuff;
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
  let domain = match args with
    | [d] -> d
    | _ -> usage "picodig" options (Some "picodig needs one argument for the domain to ask")
  in
  let dns_query = mk_query domain !query_type !query_class in
  let dns_str = exact_dump_dns_message dns_query in
  let s = Unix.socket Unix.PF_INET Unix.SOCK_DGRAM 0 in
  let host_entry = Unix.gethostbyname !host in
  let inet_addr = host_entry.Unix.h_addr_list.(0) in
  let addr = Unix.ADDR_INET (inet_addr, 53) in
  (* TODO: Check the length! *)
  ignore (Unix.sendto s dns_str 0 (String.length dns_str) [] addr);
  let res = String.make 65536 '\x00' in
  (* TODO: Use the future lwt_wrapper? *)
  let (l, _peer) = Unix.recvfrom s res 0 65536 [] in
  let answer = String.sub res 0 l in
  let input = input_of_string ~verbose:!verbose ~enrich:!enrich_style "DNS Answer" answer in
  let answer = parse_dns_message input in
  match !action with
  | All -> print_endline (print_value (value_of_dns_message answer))
  | Dig -> display_dns_message answer
