open Parsifal
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



type label = Label of string | Pointer of int (* | ResolvedPointer of int * s *)

let parse_label input =
  let n = parse_uint8 input in
  match (n land 0xc0), (n land 0x3f) with
  | 0, 0 -> false, None
  | 0xc0, hi_offset ->
    let lo_offset = parse_uint8 input in
    let offset = (hi_offset lsl 8) lor lo_offset in
    false, Some (Pointer offset)
  | 0, len -> true, Some (Label (parse_string len input))
  | _ -> raise (ParsingException (CustomException "Invalid label length", _h_of_si input))

let dump_label = function
  | Label s -> dump_varlen_string dump_uint8 s
  | Pointer p -> dump_uint16 (0xc000 land p)

let string_of_label = function
  | Label s -> s
  | Pointer p -> "@" ^ (string_of_int p)

let print_label ?indent:(indent="") ?name:(name="label") l =
  Printf.sprintf "%s%s: %s\n" indent name (string_of_label l)

let get_label = trivial_get dump_label string_of_label


type domain = label list

let parse_domain input =
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
  aux []

let rec dump_domain = function
  | [] -> dump_uint8 0
  | [Pointer _ as l] -> dump_label l
  | (Label _ as l)::r -> (dump_label l)^(dump_domain r)
  | _ -> failwith "Invalid domain"

let string_of_domain d = String.concat "." (List.map string_of_label d)

let print_domain ?indent:(indent="") ?name:(name="domain") d =
  Printf.sprintf "%s%s: %s\n" indent name (string_of_domain d)

let get_domain = trivial_get dump_domain string_of_domain



struct question = {
  qname : domain;
  qtype : query_type;
  qclass : query_class
}

struct rr = {
  rname : domain;
  rtype : rr_type;
  rclass : rr_class;
  ttl : uint32;
  rdataUNPARSED : binstring[uint16]
}


struct dns_message = {
  id : uint16;
  unparsedStuff : uint16;
  qdcount : uint16;
  ancount : uint16;
  nscount : uint16;
  arcount : uint16;
  questions : list(qdcount) of question;
  answers : list(ancount) of rr;
  authority_answers : list(nscount) of rr;
  additional_records : list(arcount) of rr
}
