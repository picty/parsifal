open Parsifal
open Dns

let mk_query name qtype =
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
    questions = [{qname = domain; qtype = qtype; qclass = RRC_IN}];
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
    (string_of_rr_type rr.rtype)
    (string_of_rr_class rr.rclass)
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



let ask host name qtype =
  let dns_query = mk_query name qtype in
  let dns_str = exact_dump_dns_message dns_query in
  let s = Unix.socket Unix.PF_INET Unix.SOCK_DGRAM 0 in
  let host_entry = Unix.gethostbyname host in
  let inet_addr = host_entry.Unix.h_addr_list.(0) in
  let addr = Unix.ADDR_INET (inet_addr, 53) in
  (* TODO: Check the length! *)
  ignore (Unix.sendto s dns_str 0 (String.length dns_str) [] addr);
  let res = String.make 65536 '\x00' in
  (* TODO: Use the future lwt_wrapper? *)
  let (l, _peer) = Unix.recvfrom s res 0 65536 [] in
  let answer = String.sub res 0 l in
  display_dns_message (parse_dns_message (input_of_string "DNS Answer" answer))

    

let _ =
  ask Sys.argv.(1) Sys.argv.(2) (rr_type_of_string Sys.argv.(3))
