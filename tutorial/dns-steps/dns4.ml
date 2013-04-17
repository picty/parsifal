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

enum query_type (16, UnknownVal UnknownQueryType) =
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


enum rr_class (16, UnknownVal UnknownRRClass) =
  | 1 -> RRC_IN, "Internet"
  | 2 -> RRC_CS, "CSNET"
  | 3 -> RRC_CH, "CHAOS"
  | 4 -> RRC_HS, "Hesiod"

enum query_class (16, UnknownVal UnknownQueryClass) =
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



let dns_query = "\x32\x65\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x04\x79\x65\x79\x65\x02\x66\x72\x00\x00\x0f\x00\x01"

let dns_answer = "\x32\x65\x81\x80\x00\x01\x00\x02\x00\x02\x00\x03\x04\x79\x65\x79\x65\x02\x66\x72\x00\x00\x0f\x00\x01\xc0\x0c\x00\x0f\x00\x01\x00\x00\x07\x08\x00\x10\x00\x0a\x0b\x70\x61\x70\x65\x72\x73\x74\x72\x65\x65\x74\xc0\x0c\xc0\x0c\x00\x0f\x00\x01\x00\x00\x07\x08\x00\x0d\x00\x0a\x08\x70\x69\x63\x74\x79\x62\x6f\x78\xc0\x0c\xc0\x0c\x00\x02\x00\x01\x00\x00\x07\x08\x00\x0b\x08\x67\x61\x72\x66\x69\x65\x6c\x64\xc0\x0c\xc0\x0c\x00\x02\x00\x01\x00\x00\x07\x08\x00\x02\xc0\x43\xc0\x43\x00\x01\x00\x01\x00\x00\x07\x08\x00\x04\xd5\xba\x39\x67\xc0\x27\x00\x01\x00\x01\x00\x00\x07\x08\x00\x04\x52\xe7\xeb\x89\xc0\x5a\x00\x01\x00\x01\x00\x00\x07\x08\x00\x04\x52\xe7\xeb\x89"


let handle_entry input =
  let dns_message = parse_dns_message input in
  print_endline (print_value (value_of_dns_message dns_message))

let _ =
  let inputs = [
    input_of_string "DNS query" dns_query;
    input_of_string "DNS answer" dns_answer;
  ] in
  List.iter handle_entry inputs
