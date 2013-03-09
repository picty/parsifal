open Lwt
open Parsifal

enum asn1_class (2, Exception UnknownAsn1Class) =
  | 0 -> C_Universal, "Universal"
  | 1 -> C_Application, "Application"
  | 2 -> C_ContextSpecific, "Context Specific"
  | 3 -> C_Private, "Private"

enum asn1_tag (5, UnknownVal T_Unknown) =
  | 0 -> T_EndOfContents, "EOC"
  | 1 -> T_Boolean, "Boolean"
  | 2 -> T_Integer, "Integer"
  | 3 -> T_BitString, "Bit String"
  | 4 -> T_OctetString, "Octet String"
  | 5 -> T_Null, "Null"
  | 6 -> T_OId, "OId"
  | 7 -> T_ObjectDescriptor, "Object Descriptor"
  | 8 -> T_External, "External"
  | 9 -> T_Real, "Real"
  | 10 -> T_Enumerated, "Enumerated"
  | 11 -> T_EmbeddedPDV, "EmbeddedPDV"
  | 12 -> T_UTF8String, "UTF8 String"
  | 13 -> T_RelativeOId, "Relative OId"
  | 16 -> T_Sequence, "Sequence"
  | 17 -> T_Set, "Set"
  | 18 -> T_NumericString, "Numeric String"
  | 19 -> T_PrintableString, "Printable String"
  | 20 -> T_T61String, "T61 String"
  | 21 -> T_VideoString, "Video String"
  | 22 -> T_IA5String, "IA5 String"
  | 23 -> T_UTCTime, "UTC Time"
  | 24 -> T_GeneralizedTime, "Generalized Time"
  | 25 -> T_GraphicString, "Graphic String"
  | 26 -> T_VisibleString, "Visible String"
  | 27 -> T_GeneralString, "General String"
  | 28 -> T_UniversalString, "Universal String"
  | 29 -> T_UnspecifiedCharacterString, "Unspecified Character String"
  | 30 -> T_BMPString, "BMP String"



let prim_or_cons = function false -> "prim" | true -> "cons"
let print_header = function
  | (C_Universal, false, (T_EndOfContents | T_Boolean | T_Integer | T_BitString | T_OctetString | 
                          T_Null | T_OId | T_ObjectDescriptor | T_External | T_Real | T_Enumerated |
                          T_EmbeddedPDV | T_UTF8String | T_RelativeOId | T_NumericString |
                          T_PrintableString | T_T61String | T_VideoString | T_IA5String |
                          T_UTCTime | T_GeneralizedTime | T_GraphicString | T_VisibleString |
                          T_GeneralString | T_UniversalString | T_UnspecifiedCharacterString |
                          T_BMPString as t)) -> string_of_asn1_tag t

  | (C_Universal, true, (T_Sequence | T_Set as t)) -> string_of_asn1_tag t
  | C_Universal, isC, t -> Printf.sprintf "[UNIV %d] %s" (int_of_asn1_tag t) (prim_or_cons isC)
  | C_Application, isC, t -> Printf.sprintf "[APP %d] %s" (int_of_asn1_tag t) (prim_or_cons isC)
  | C_ContextSpecific, isC, t -> Printf.sprintf "[%d] %s" (int_of_asn1_tag t) (prim_or_cons isC)
  | C_Private, isC, t -> Printf.sprintf "[PRIVATE %d] %s" (int_of_asn1_tag t) (prim_or_cons isC)

type der_info = {
  a_offset : int;
  a_hlen : int;
  a_length : int;
  a_class : asn1_class;
  a_isConstructed : bool;
  a_tag : asn1_tag;
}


type asn1_exception =
  | UnexpectedHeader of (asn1_class * bool * asn1_tag) * (asn1_class * bool * asn1_tag) option
  | BooleanNotInNormalForm
  | IntegerNotInNormalForm
  | IntegerOverflow
  | NullNotInNormalForm
  | OIdNotInNormalForm
  | BitStringNotInNormalForm of string
  | InvalidUTCTime
  | UnknownUniversalObject of bool * asn1_tag

let print_asn1_exception = function
  | UnexpectedHeader (h, None) ->
    Printf.sprintf "UnexpectedHeader (%s)" (print_header h)
  | UnexpectedHeader (h, Some exp_h) ->
    Printf.sprintf "UnexpectedHeader (%s instead of %s)" (print_header h) (print_header exp_h)
  | BooleanNotInNormalForm -> "BooleanNotInNormalForm"
  | IntegerNotInNormalForm -> "IntegerNotInNormalForm"
  | IntegerOverflow -> "IntegerOverflow"
  | NullNotInNormalForm -> "NullNotInNormalForm"
  | OIdNotInNormalForm -> "OIdNotInNormalForm"
  | BitStringNotInNormalForm details -> "BitStringNotInNormalForm (" ^ details ^ ")"
  | InvalidUTCTime -> "InvalidUTCTime"
  | UnknownUniversalObject (isC, t) ->
    Printf.sprintf "UnknownUniversalObject (%s)" (print_header (C_Universal, isC, t))


let fatal_error e i = raise (ParsingException (CustomException (print_asn1_exception e), _h_of_si i))
let warning_h f e h = f (string_of_exception (CustomException (print_asn1_exception e)) h)
let warning e i = warning_h i.err_fun e (_h_of_si i)


(* Header *)

let extract_der_class (x : int) : asn1_class =
  let i = x lsr 6 in
  asn1_class_of_int i

let extract_der_isConstructed (x : int) : bool =
  let i = (x lsr 5) land 1 in
  i = 1

let extract_der_longtype input : asn1_tag  =
  let rec aux accu =
    let byte = parse_byte input in
    let new_accu = (accu lsl 7) lor (byte land 0x7f) in
    if (byte land 0x80) = 0
    then new_accu
    else aux new_accu
  in T_Unknown (aux 0)

let extract_der_header input : (asn1_class * bool * asn1_tag) =
  let hdr = parse_byte input in
  let c = extract_der_class hdr in
  let isC = extract_der_isConstructed hdr in
  let hdr_t = hdr land 31 in
  let t =
    if (hdr_t < 0x1f)
    then begin
      if c = C_Universal
      then asn1_tag_of_int hdr_t
      else T_Unknown hdr_t
    end else extract_der_longtype input
  in (c, isC, t)

let extract_der_length input =
  let first = parse_byte input in
  if first land 0x80 = 0
  then first
  else begin
    let accu = ref 0 in
    for i = 1 to (first land 0x7f) do
      accu := (!accu lsl 8) lor (parse_byte input);
    done;
    !accu
  end


let check_header ((exp_c, exp_isC, exp_t) as exp_hdr) input ((c, isC, t) as hdr) =
  if hdr <> exp_hdr
  then fatal_error (UnexpectedHeader ((c, isC, t), Some (exp_c, exp_isC, exp_t))) input

let _extract_der_object name header_constraint parse_content input =
  let offset = input.cur_base + input.cur_offset in
  let old_cur_offset = input.cur_offset in
  let c, isC, t = extract_der_header input in
  check_header header_constraint input (c, isC, t);
  let len = extract_der_length input in
  let hlen = input.cur_offset - old_cur_offset in
  let new_input = get_in input name len in
  let der_info = {
    a_offset = offset;
    a_hlen = hlen;
    a_length = len;
    a_class = c;
    a_isConstructed = isC;
    a_tag = t;
  }
  and raw_string () = String.sub input.str offset (len+hlen) in
  let res = parse_content new_input in
  get_out input new_input;
  res, der_info, raw_string

let extract_der_object name header_constraint parse_content input =
  let res, _, _ = _extract_der_object name header_constraint parse_content input in
  res


let dump_der_header (c, isC, t) =
  let t_int = int_of_asn1_tag t in
  if t_int >= 0x1f then raise (ParsingException (NotImplemented "long type", []));
  let h = ((int_of_asn1_class c) lsl 6) lor
    (if isC then 0x20 else 0) lor t_int in
  String.make 1 (char_of_int h)

let dump_der_length l =
  let rec compute_len accu = function
    | 0 -> accu
    | lg -> compute_len (accu + 1) (lg lsr 8)
  in
  let rec aux res i = function
    | 0 -> ()
    | lg ->
      res.[i] <- char_of_int (lg land 0xff);
      aux res (i-1) (lg lsr 8)
  in
  if l < 0x80
  then String.make 1 (char_of_int l)
  else
    let len_len = compute_len 0 l in
    let res = String.make (len_len + 1) (char_of_int (len_len lor 0x80)) in
    aux res len_len l;
    res

let produce_der_object hdr dump_content v =
  let content_dumped = dump_content v in
  (dump_der_header hdr) ^ (dump_der_length (String.length content_dumped)) ^ content_dumped



let lwt_extract_der_longtype input =
  let rec aux accu =
    lwt_parse_byte input >>= fun byte ->
    let new_accu = (accu lsl 7) lor (byte land 0x7f) in
    if (byte land 0x80) = 0
    then return new_accu
    else aux new_accu
  in aux 0 >>= fun x -> return (T_Unknown x)

let lwt_extract_der_header input =
  lwt_parse_byte input >>= fun hdr ->
  let c = extract_der_class hdr in
  let isC = extract_der_isConstructed hdr in
  let hdr_t = hdr land 31 in
  if (hdr_t < 0x1f)
  then begin
    if c = C_Universal
    then return (c, isC, asn1_tag_of_int hdr_t)
    else return (c, isC, T_Unknown hdr_t)
  end else begin
    lwt_extract_der_longtype input >>= fun t ->
    return (c, isC, t)
  end

let lwt_extract_der_length input =
  lwt_parse_byte input >>= fun first ->
  if first land 0x80 = 0
  then return first
  else begin
    let rec aux accu = function
      | 0 -> return accu
      | i ->
	lwt_parse_byte input >>= fun x ->
	aux ((accu lsl 8) lor x) (i-1)
    in aux 0 (first land 0x7f)
  end

let _lwt_extract_der_object name header_constraint parse_content input =
  let offset = input.lwt_offset in
  lwt_extract_der_header input >>= fun (c, isC, t) ->
  let fake_input = {
    str = "";
    cur_name = name;
    cur_base = 0;
    cur_offset = offset;
    cur_length = -1;
    enrich = input.lwt_enrich;
    history = [];
    err_fun = input.lwt_err_fun
  } in
  check_header header_constraint fake_input (c, isC, t);
  let hlen = input.lwt_offset - offset in
  lwt_extract_der_length input >>= fun len ->
  lwt_get_in input name len >>= fun new_input ->
  let der_info = {
    a_offset = offset;
    a_hlen = hlen;
    a_length = len;
    a_class = c;
    a_isConstructed = isC;
    a_tag = t;
  }
  and raw_string () = (dump_der_header (c, isC, t)) ^ (dump_der_length len) ^ new_input.str in
  let res = parse_content new_input in
  lwt_get_out input new_input >>= fun () ->
  return (res, der_info, raw_string)

let lwt_extract_der_object name header_constraint parse_content input =
  _lwt_extract_der_object name header_constraint parse_content input >>= fun (res, _, _) ->
  return res


(* Sequence/Set of *)

(* TODO: min/max *)
let extract_der_seqof name header_constraint (* min max *) parse_content input =
  let rec parse_aux accu input =
    if eos input
    then List.rev accu
    else
      let next = parse_content input in
      parse_aux (next::accu) input
  in extract_der_object name header_constraint (parse_aux []) input

let lwt_extract_der_seqof name header_constraint (* min max *) lwt_parse_content input =
  let rec lwt_parse_aux accu input =
    if eos input
    then return (List.rev accu)
    else
      lwt_parse_content input >>= fun next ->
      lwt_parse_aux (next::accu) input
  in lwt_extract_der_object name header_constraint (lwt_parse_aux []) input

let produce_der_seqof header_constraint dump_content l =
  let rec dump_der_list_aux accu = function
    | [] -> String.concat "" (List.rev accu)
    | x::r ->
      let next = dump_content x in
      dump_der_list_aux (next::accu) r
  in
  produce_der_object header_constraint (dump_der_list_aux []) l
