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
  | 16 -> RRT_TXT, "TXT"
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

let dump_dns_dcontext buf = {
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


struct soa_rdata [both_param ctx; novalueof] = {
  soa_mname : domain[ctx];
  soa_rname : domain[ctx];
  soa_serial: uint32;
  soa_refresh : uint32;
  soa_retry : uint32;
  soa_expire : uint32;
  soa_minimum : uint32
}

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
    "soa_serial", VInt soa_rdata.soa_serial;
    "soa_refresh", VInt soa_rdata.soa_refresh;
    "soa_retry", VInt soa_rdata.soa_retry;
    "soa_expire", VInt soa_rdata.soa_expire;
    "soa_minimum", VInt soa_rdata.soa_minimum;
  ]


struct hinfo_rdata = {
  hinfo_cpu : string[uint8];
  hinfo_os : string[uint8];
}

struct mx_rdata [both_param ctx; novalueof] = {
  mx_preference : uint16;
  mx_host : domain[ctx]
}

let value_of_mx_rdata mx_rdata =
  let content = string_of_domain mx_rdata.mx_host in
  let domain = String.concat "." content in
  VRecord [
    "@name", VString ("mx_rdata", false);
    "@string_of", VString (Printf.sprintf "%d %s" mx_rdata.mx_preference domain, false);
    "mx_preference", VInt mx_rdata.mx_preference;
    "mx_host", value_of_domain mx_rdata.mx_host;
  ]


alias txt_rdata [novalueof] = list of string[uint8]
let value_of_txt_rdata txt_rdata = VString (String.concat "." txt_rdata, false)


union rdata [enrich; both_param ctx] (UnparsedRData) =
  | RRT_A -> Address of ipv4
  | RRT_NS -> Domain of domain[ctx]
  | RRT_CNAME -> Domain of domain[ctx]
  | RRT_SOA -> SOA of soa_rdata[ctx]
  | RRT_NULL -> NullRData of binstring
  | RRT_PTR -> Domain of domain[ctx]
  | RRT_HINFO -> HInfo of hinfo_rdata
  | RRT_MX -> MX of mx_rdata[ctx]
  | RRT_TXT -> TXT of txt_rdata



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


enum opcode (4, UnknownVal UnknownOpcode) =
  | 0 -> StandardQuery
  | 1 -> InverseQuery
  | 2 -> ServerStatusRequest

enum rcode (4, UnknownVal UnkownRCode) =
  | 0 -> RC_NoError, "NOERROR"
  | 1 -> RC_FormatError, "FORMERR"
  | 2 -> RC_ServerFailure, "SERVFAIL"
  | 3 -> RC_NameError, "NXDOMAIN"
  | 4 -> RC_NotImplemented, "NOTIMP"
  | 5 -> RC_Refused, "REFUSED"


struct dns_message [top] = {
  parse_checkpoint ctx : dns_pcontext;
  dump_checkpoint ctx : dns_dcontext;
  id : uint16;
  qr : bit_bool;
  opcode : opcode;
  aa : bit_bool;
  tc : bit_bool;
  rd : bit_bool;
  ra : bit_bool;
  z : bit_int[3];
  rcode : rcode;
  qdcount : uint16;
  ancount : uint16;
  nscount : uint16;
  arcount : uint16;
  questions : list(qdcount) of question[ctx];
  answers : list(ancount) of rr[ctx];
  authority_answers : list(nscount) of rr[ctx];
  additional_records : list(arcount) of rr[ctx]
}
