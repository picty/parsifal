open Parsifal
open BasePTypes
open PTypes


enum rr_type (16, UnknownVal UnknownQueryType) =
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
  | 252 -> RRT_AXFR, "AXFR"
  | 253 -> RRT_MAILB, "MAILB"
  | 254 -> RRT_MAILA, "MAILA"
  | 255 -> RRT_ANYTYPE, "*"

enum rr_class (16, UnknownVal UnknownQueryClass) =
  | 1 -> RRC_IN, "IN"
  | 2 -> RRC_CS, "CSNET"
  | 3 -> RRC_CH, "CHAOS"
  | 4 -> RRC_HS, "Hesiod"
  | 255 -> RRC_ANYCLASS, "*"


type domain =
  | DomainLabel of string * domain
  | DomainPointer of int
  | DomainEnd


type dns_pcontext = {
  base_offset : int;
  direct_resolver : (int, domain) Hashtbl.t;
}

type dns_dcontext = {
  output_offset : int;
  reverse_resolver : (domain, int) Hashtbl.t;
}

let parse_dns_pcontext input = {
  base_offset = input.cur_base + input.cur_offset;
  direct_resolver = Hashtbl.create 10;
}

let dump_dns_dcontext buf _ = {
  output_offset = POutput.length buf;
  reverse_resolver = Hashtbl.create 10;
}

let resolve_domains = ref true
let compress_domains = ref true

let rec parse_domain ctx input =
  let o = input.cur_base + input.cur_offset in
  let n = parse_uint8 input in
  match (n land 0xc0), (n land 0x3f) with
  | 0, 0 -> DomainEnd
  | 0xc0, hi_offset ->
    let lo_offset = parse_uint8 input in
    let offset = (hi_offset lsl 8) lor lo_offset in
    let d = DomainPointer offset in
    if should_enrich resolve_domains input.enrich
    then hash_get ctx.direct_resolver offset d
    else d
  | 0, len ->
    let label = parse_string len input in
    let rem = parse_domain ctx input in
    let d = DomainLabel (label, rem) in
    if should_enrich resolve_domains input.enrich
    then Hashtbl.replace ctx.direct_resolver (o - ctx.base_offset) d;
    d
  | _ -> raise (ParsingException (CustomException "Invalid label length", _h_of_si input))

let rec dump_domain ctx buf = function
  | DomainEnd -> dump_uint8 buf 0
  | DomainPointer p -> dump_uint16 buf (0xc000 land p)
  | (DomainLabel (l, r)) as d ->
    if !compress_domains then begin
      try
	dump_domain ctx buf (DomainPointer (Hashtbl.find ctx.reverse_resolver d))
      with Not_found ->
	Hashtbl.replace ctx.reverse_resolver d (POutput.length buf - ctx.output_offset);
	dump_varlen_string dump_uint8 buf l;
	dump_domain ctx buf r
    end else begin
      dump_varlen_string dump_uint8 buf l;
      dump_domain ctx buf r
    end

let rec string_of_domain = function
  | DomainLabel (s, rem) -> s::(string_of_domain rem)
  | DomainPointer p -> ["@" ^ (string_of_int p)]
  | DomainEnd -> []

let value_of_domain d =
  let content = string_of_domain d in
  VRecord [
    "@name", VString ("domain", false);
    "@string_of", VString (String.concat "." content, false);
    "content", VList (List.map value_of_string content)
  ]


struct soa_rdata [both_param ctx] = {
  soa_mname : domain[ctx];
  soa_rname : domain[ctx];
  soa_serial: uint32;
  soa_refresh : uint32;
  soa_retry : uint32;
  soa_expire : uint32;
  soa_minimum : uint32
}

(* TODO: value_of overload is a hack. *)
let value_of_soa_rdata soa_rdata =
  let mname = String.concat "." (string_of_domain soa_rdata.soa_mname) in
  let rname = String.concat "." (string_of_domain soa_rdata.soa_rname) in
  VRecord [
    "@name", VString ("soa_rdata", false);
    "@string_of", VString (Printf.sprintf "%s %s %d %d %d %d %d" mname  rname
			     soa_rdata.soa_serial soa_rdata.soa_refresh
			     soa_rdata.soa_retry soa_rdata.soa_expire
			     soa_rdata.soa_minimum, false);
    "soa_mname", value_of_domain soa_rdata.soa_mname;
    "soa_rname", value_of_domain soa_rdata.soa_rname;
    "soa_serial", VSimpleInt soa_rdata.soa_serial;
    "soa_refresh", VSimpleInt soa_rdata.soa_refresh;
    "soa_retry", VSimpleInt soa_rdata.soa_retry;
    "soa_expire", VSimpleInt soa_rdata.soa_expire;
    "soa_minimum", VSimpleInt soa_rdata.soa_minimum;
  ]


struct mx_rdata [both_param ctx] = {
  mx_preference : uint16;
  mx_host : domain[ctx]
}

(* TODO: value_of overload is a hack. *)
let value_of_mx_rdata mx_rdata =
  let content = string_of_domain mx_rdata.mx_host in
  let domain = String.concat "." content in
  VRecord [
    "@name", VString ("mx_rdata", false);
    "@string_of", VString (Printf.sprintf "%d %s" mx_rdata.mx_preference domain, false);
    "mx_preference", VSimpleInt mx_rdata.mx_preference;
    "mx_host", value_of_domain mx_rdata.mx_host;
  ]

union rdata [enrich; both_param ctx] (UnparsedRData) =
  | RRT_A -> Address of ipv4
  | RRT_NS -> Domain of domain[ctx]
  | RRT_CNAME -> Domain of domain[ctx]
  | RRT_SOA -> SOA of soa_rdata[ctx]
  | RRT_NULL -> NullRData of binstring
  | RRT_PTR -> Domain of domain[ctx]
  | RRT_MX -> MX of mx_rdata[ctx]



struct question [both_param ctx] = {
  qname : domain[ctx];
  qtype : rr_type;
  qclass : rr_class
}

struct rr [both_param ctx] = {
  rname : domain[ctx];
  rtype : rr_type;
  rclass : rr_class;
  ttl : uint32;
  rdata : container[uint16] of rdata(BOTH ctx; rtype)
}


type dns_flags = {
  qr : bool;
  opcode : int;
  aa : bool;
  tc : bool;
  rd : bool;
  ra : bool;
  z : int;
  rcode : int;
}

let parse_dns_flags input =
  let qr = parse_bits 1 input in
  let opcode = parse_bits 4 input in
  let aa = parse_bits 1 input in
  let tc = parse_bits 1 input in
  let rd = parse_bits 1 input in
  let ra = parse_bits 1 input in
  let z = parse_bits 3 input in
  let rcode = parse_bits 4 input in
  { qr = qr = 1; opcode = opcode; aa = aa = 1; tc = tc = 1;
    rd = rd = 1; ra = ra = 1; z = z; rcode = rcode }

let dump_dns_flags buf flags =
  POutput.add_bits buf 1 (if flags.qr then 1 else 0);
  POutput.add_bits buf 4 flags.opcode;
  POutput.add_bits buf 1 (if flags.aa then 1 else 0);
  POutput.add_bits buf 1 (if flags.tc then 1 else 0);
  POutput.add_bits buf 1 (if flags.rd then 1 else 0);
  POutput.add_bits buf 1 (if flags.ra then 1 else 0);
  POutput.add_bits buf 3 flags.z;
  POutput.add_bits buf 4 flags.rcode

let value_of_dns_flags flags =
  VRecord [
    "@name", VString ("dns_flags", false);
    "qr", VBool flags.qr;
    "opcode", VSimpleInt flags.opcode;
    "aa", VBool flags.aa;
    "tc", VBool flags.tc;
    "rd", VBool flags.rd;
    "ra", VBool flags.ra;
    "z", VSimpleInt flags.z;
    "rcode", VSimpleInt flags.rcode;
  ]
		 

struct dns_message [with_exact] = {
  parse_checkpoint ctx : dns_pcontext;
  dump_checkpoint ctx : dns_dcontext;
  id : uint16;
  flags : dns_flags;
  qdcount : uint16;
  ancount : uint16;
  nscount : uint16;
  arcount : uint16;
  questions : list(qdcount) of question[ctx];
  answers : list(ancount) of rr[ctx];
  authority_answers : list(nscount) of rr[ctx];
  additional_records : list(arcount) of rr[ctx]
}
