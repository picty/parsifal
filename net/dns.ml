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



type dns_context = {
  initial_offset : int;
  previous_labels : (int, string list) Hashtbl.t;
(*  rev_previous_labels : (string list, int) Hashtbl.t;   TODO: Useful for dump? *)
}

let mk_dns_context init_offset = {
  initial_offset = init_offset;
  previous_labels = Hashtbl.create 10;
}


type label = Label of string | Pointer of int

let parse_label input =
  let n = parse_uint8 input in
  match (n land 0xc0), (n land 0x3f) with
  | 0, 0 -> false, None
  | 0xc0, hi_offset ->
    let lo_offset = parse_uint8 input in
    let offset = (hi_offset lsl 8) lor lo_offset in
    false, Some (Pointer offset)
  | 0, len ->
    true, Some (Label (parse_string len input))
  | _ -> raise (ParsingException (CustomException "Invalid label length", _h_of_si input))

let dump_label = function
  | Label s -> dump_varlen_string dump_uint8 s
  | Pointer p -> dump_uint16 (0xc000 land p)

let string_of_label = function
  | Label s -> s
  | Pointer p -> "@" ^ (string_of_int p)

let value_of_label l = VString (string_of_label l, false)


type domain =
  | RawDomain of label list
  | UnfoldedDomain of string list


let rec resolve tbl = function
  | [] -> 0, []
  | [Pointer p] -> 0, Hashtbl.find tbl p
  | (Label l)::r ->
    let n_labels, resolved_r = resolve tbl r in
    (n_labels + 1, l::resolved_r)
  | _ -> (* TODO *) failwith "Invalid domain"

let rec record_new_offsets tbl offset = function
  | 0, _ -> ()
  | n_labels, ((l::r) as d) ->
    Hashtbl.replace tbl offset d;
    record_new_offsets tbl (offset + 1 + (String.length l)) (n_labels - 1, r)
  | _ -> (* TODO *) failwith "Internal error: record_new_offsets"

let unfold_domain o ctx ls = match ctx with
  | None -> RawDomain ls
  | Some context ->
    try
      let (_, res) as record_data = resolve context.previous_labels ls in
      record_new_offsets context.previous_labels (o - context.initial_offset) record_data;
      UnfoldedDomain res
    with
      Not_found ->
	(* TODO: Should not happen *)
	RawDomain ls

let parse_domain ctx input =
  let rec aux accu =
    let do_continue, label = parse_label input in
    let new_accu = match label with
      | None -> accu
      | Some l -> l::accu
    in
    if do_continue
    then aux new_accu
    else List.rev new_accu
  in
  let domain_start = input.cur_offset + input.cur_base in
  let res = aux [] in
  unfold_domain domain_start ctx res

let rec dump_raw_domain = function
  | [] -> dump_uint8 0
  | [Pointer _ as l] -> dump_label l
  | (Label _ as l)::r -> (dump_label l)^(dump_raw_domain r)
  | _ -> (* TODO *) failwith "Invalid domain"

let dump_domain = function
  | RawDomain d -> dump_raw_domain d
  | UnfoldedDomain _ -> failwith "NotImplemented: dump_unfolded_domain"

let value_of_domain d =
  let content = match d with
    | RawDomain d -> List.map string_of_label d
    | UnfoldedDomain d -> d
  in
  VRecord [
    "@name", VString ("domain", false);
    "@string_of", VString (String.concat "." content, false);
    "content", VList (List.map (value_of_string false) content)
  ]


struct mx_rdata [param dns_context] = {
  mx_preference : uint16;
  mx_host : domain(dns_context)
}


union rdata [enrich; param dns_context] (UnparsedRData) =
  | RRT_A -> Address of ipv4
  | RRT_NS -> Domain of domain(dns_context)
  (* | 3 -> RRT_MD, "MD" *)
  (* | 4 -> RRT_MF, "MF" *)
  | RRT_CNAME -> Domain of domain(dns_context)
  (* | 6 -> RRT_SOA, "SOA" *)
  (* | 7 -> RRT_MB, "MB" *)
  (* | 8 -> RRT_MG, "MG" *)
  (* | 9 -> RRT_MR, "MR" *)
  (* | 10 -> RRT_NULL, "NULL" *)
  (* | 11 -> RRT_WKS, "WKS" *)
  | RRT_PTR -> Domain of domain(dns_context)
  (* | 13 -> RRT_HINFO, "HINFO" *)
  (* | 14 -> RRT_MINFO, "MINFO" *)
  | RRT_MX -> MX of mx_rdata(dns_context)


struct question [param dns_context] = {
  qname : domain(dns_context);
  qtype : query_type;
  qclass : query_class
}

struct rr [param dns_context] = {
  rname : domain(dns_context);
  rtype : rr_type;
  rclass : rr_class;
  ttl : uint32;
  rdata : container[uint16] of rdata(dns_context; rtype)
}


struct dns_message [param dns_context] = {
  id : uint16;
  unparsedStuff : uint16;
  qdcount : uint16;
  ancount : uint16;
  nscount : uint16;
  arcount : uint16;
  questions : list(qdcount) of question(dns_context);
  answers : list(ancount) of rr(dns_context);
  authority_answers : list(nscount) of rr(dns_context);
  additional_records : list(arcount) of rr(dns_context)
}

(* TODO: Automagically compress this struct (only one field!) *)
struct smart_dns_message = {
  parse_checkpoint init_offset : save_offset;
  msg : dns_message(Some (mk_dns_context init_offset))
}

alias dumb_dns_message = dns_message(None)
