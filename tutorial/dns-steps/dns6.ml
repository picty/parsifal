open Parsifal
open BasePTypes
open PTypes


enum rr_type (16, UnknownVal UnknownRRType) =
  | 1 -> RRT_A, "A"
  | 2 -> RRT_NS, "NS"
  | 3 -> RRT_MD, "MD"
  | 4 -> RRT_MF, "MF"
  | 5 -> RRT_CNAME, "CNAME"
  | 6 -> RRT_SOA, "SOA"
  | 7 -> RRT_MB, "MB"
  | 8 -> RRT_MG, "MG"
  | 9 -> RRT_MR, "MR"
  | 10 -> RRT_NULL, "NULL"
  | 11 -> RRT_WKS, "WKS"
  | 12 -> RRT_PTR, "PTR"
  | 13 -> RRT_HINFO, "HINFO"
  | 14 -> RRT_MINFO, "MINFO"
  | 15 -> RRT_MX, "MX"

enum query_type [with_lwt] (16, UnknownVal UnknownQueryType) =
  | 1 -> QT_A, "A"
  | 2 -> QT_NS, "NS"
  | 3 -> QT_MD, "MD"
  | 4 -> QT_MF, "MF"
  | 5 -> QT_CNAME, "CNAME"
  | 6 -> QT_SOA, "SOA"
  | 7 -> QT_MB, "MB"
  | 8 -> QT_MG, "MG"
  | 9 -> QT_MR, "MR"
  | 10 -> QT_NULL, "NULL"
  | 11 -> QT_WKS, "WKS"
  | 12 -> QT_PTR, "PTR"
  | 13 -> QT_HINFO, "HINFO"
  | 14 -> QT_MINFO, "MINFO"
  | 15 -> QT_MX, "MX"
  | 252 -> QT_AXFR, "AXFR"
  | 253 -> QT_MAILB, "MAILB"
  | 254 -> QT_MAILA, "MAILA"
  | 255 -> QT_ANYTYPE, "*"


enum rr_class [with_lwt] (16, UnknownVal UnknownRRClass) =
  | 1 -> RRC_IN, "Internet"
  | 2 -> RRC_CS, "CSNET"
  | 3 -> RRC_CH, "CHAOS"
  | 4 -> RRC_HS, "Hesiod"

enum query_class [with_lwt] (16, UnknownVal UnknownQueryClass) =
  | 1 -> QC_IN, "Internet"
  | 2 -> QC_CS, "CSNET"
  | 3 -> QC_CH, "CHAOS"
  | 4 -> QC_HS, "Hesiod"
  | 255 -> QC_ANYCLASS, "*"


type domain =
  | DomainLabel of (int * string) * domain
  | DomainPointer of int
  | DomainEnd


type dns_context = {
  base_offset : int;
  direct_resolver : (int, domain) Hashtbl.t;
  reverse_resolver : (domain, int) Hashtbl.t;
}

let parse_dns_context input = {
    base_offset = input.cur_base + input.cur_offset;
    direct_resolver = Hashtbl.create 10;
    reverse_resolver = Hashtbl.create 10
  }


let resolve_domains = ref true

let rec parse_raw_domain input =
  let o = input.cur_base + input.cur_offset in
  let n = parse_uint8 input in
  match (n land 0xc0), (n land 0x3f) with
  | 0, 0 -> DomainEnd
  | 0xc0, hi_offset ->
    let lo_offset = parse_uint8 input in
    let offset = (hi_offset lsl 8) lor lo_offset in
    DomainPointer offset
  | 0, len ->
    let label = parse_string len input in
    let rem = parse_raw_domain input in
    DomainLabel ((o, label), rem)
  | _ -> raise (ParsingException (CustomException "Invalid label length", _h_of_si input))

let parse_domain ctx input =
  let rec resolve_labels = function
    | DomainEnd -> DomainEnd
    | (DomainPointer p) as d ->
      hash_get ctx.direct_resolver (p - ctx.base_offset) d
    | DomainLabel ((o, l), rem) ->
      let real_o = o - ctx.base_offset in
      let subd = resolve_labels rem in
      let new_d = DomainLabel ((real_o, l), subd) in
      Hashtbl.replace ctx.direct_resolver o new_d;
      Hashtbl.replace ctx.reverse_resolver new_d o;
      new_d
  in
  let raw_res = parse_raw_domain input in
  if should_enrich resolve_domains input.enrich
  then resolve_labels raw_res
  else raw_res

let rec dump_domain = function
  | DomainEnd -> dump_uint8 0
  | DomainPointer p -> dump_uint16 (0xc000 land p)
    (* TODO: Compress! *)
  | DomainLabel ((_, l), r) -> (dump_varlen_string dump_uint8 l)^(dump_domain r)

let rec string_of_domain = function
  | DomainLabel ((_, s), rem) -> s::(string_of_domain rem)
  | DomainPointer p -> ["@" ^ (string_of_int p)]
  | DomainEnd -> []

let value_of_domain d =
  let content = string_of_domain d in
  VRecord [
    "@name", VString ("domain", false);
    "@string_of", VString (String.concat "." content, false);
    "content", VList (List.map (value_of_string false) content)
  ]


struct mx_rdata [param ctx] = {
  mx_preference : uint16;
  mx_host : domain(ctx)
}


union rdata [enrich; param ctx] (UnparsedRData) =
  | RRT_A -> Address of ipv4
  | RRT_NS -> Domain of domain(ctx)
  (* | 3 -> RRT_MD, "MD" *)
  (* | 4 -> RRT_MF, "MF" *)
  | RRT_CNAME -> Domain of domain(ctx)
  (* | 6 -> RRT_SOA, "SOA" *)
  (* | 7 -> RRT_MB, "MB" *)
  (* | 8 -> RRT_MG, "MG" *)
  (* | 9 -> RRT_MR, "MR" *)
  (* | 10 -> RRT_NULL, "NULL" *)
  (* | 11 -> RRT_WKS, "WKS" *)
  | RRT_PTR -> Domain of domain(ctx)
  (* | 13 -> RRT_HINFO, "HINFO" *)
  (* | 14 -> RRT_MINFO, "MINFO" *)
  | RRT_MX -> MX of mx_rdata(ctx)



struct question [param ctx] = {
  qname : domain(ctx);
  qtype : query_type;
  qclass : query_class
}

struct rr [param ctx] = {
  rname : domain(ctx);
  rtype : rr_type;
  rclass : rr_class;
  ttl : uint32;
  rdata : container[uint16] of rdata(ctx; rtype)
}


(* TODO! *)
(* How to update the reverse hashtbl correctly while dumping ? Using a buffer instead of a string? *)
(* We would also need a dump_checkpoint to initialize the c.base_offset *)
(* - dump_checkpoint *)
(* - rewrite params handling *)
(* - use different ctxs checkpoints for parse/dump *)
(* - rewrite dump_* as functions working on a buffer *)
(* - write a wrapper, dump : (Buffer.t -> 'a -> unit) -> string *)

struct dns_message = {
  parse_checkpoint ctx : dns_context;
  id : uint16;
  unparsedStuff : uint16;
  qdcount : uint16;
  ancount : uint16;
  nscount : uint16;
  arcount : uint16;
  questions : list(qdcount) of question(ctx);
  answers : list(ancount) of rr(ctx);
  authority_answers : list(nscount) of rr(ctx);
  additional_records : list(arcount) of rr(ctx)
}


let mk_query name qtype =
  let rec domain_of_stringlist = function
    | [] -> DomainEnd
    | l::r -> DomainLabel ((0, l), domain_of_stringlist r)
  in
  let domain = domain_of_stringlist (string_split '.' name) in
  {
    id = 1234;
    unparsedStuff = 0x0100;
    qdcount = 1;
    ancount = 0; nscount = 0; arcount = 0;
    questions = [{qname = domain; qtype = qtype; qclass = QC_IN}];
    answers = []; authority_answers = []; additional_records = [];
  }


let display_question q =
  Printf.printf "%-30s         %-10s %-10s\n"
    (String.concat "." (string_of_domain q.qname))
    (string_of_query_type q.qtype)
    (string_of_query_class q.qclass)

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
  let dns_str = dump_dns_message dns_query in
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
  ask Sys.argv.(1) Sys.argv.(2) (query_type_of_string Sys.argv.(3))
