open Parsifal

enum asn1_class (2, Exception) =
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

let h_sequence = (C_Universal, true, T_Sequence)


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
    for _i = 1 to (first land 0x7f) do
      accu := (!accu lsl 8) lor (parse_byte input);
    done;
    !accu
  end


let check_header ((exp_c, exp_isC, exp_t) as exp_hdr) input ((c, isC, t) as hdr) =
  if hdr <> exp_hdr
  then fatal_error (UnexpectedHeader ((c, isC, t), Some (exp_c, exp_isC, exp_t))) input

let extract_der_object header_constraint name parse_content input =
  let c, isC, t = extract_der_header input in
  check_header header_constraint input (c, isC, t);
  let len = extract_der_length input in
  let new_input = get_in input name len in
  let res = parse_content new_input in
  get_out input new_input;
  res


let dump_der_header buf (c, isC, t) =
  let t_int = int_of_asn1_tag t in
  if t_int >= 0x1f then raise (ParsingException (NotImplemented "long type", []));
  let h = ((int_of_asn1_class c) lsl 6) lor
    (if isC then 0x20 else 0) lor t_int in
  POutput.add_byte buf h

let dump_der_length buf l =
  let rec compute_len accu = function
    | 0 -> accu
    | lg -> compute_len (accu + 1) (lg lsr 8)
  in
  let rec aux res i = function
    | 0 -> ()
    | lg ->
      Bytes.set res i (char_of_int (lg land 0xff));
      aux res (i-1) (lg lsr 8)
  in
  if l < 0x80
  then POutput.add_byte buf l
  else
    let len_len = compute_len 0 l in
    let res = Bytes.make (len_len + 1) (char_of_int (len_len lor 0x80)) in
    aux res len_len l;
    POutput.add_bytes buf res

let produce_der_object hdr dump_content buf v =
  dump_der_header buf hdr;
  let tmp_buf = POutput.create () in
  dump_content tmp_buf v;
  dump_der_length buf (POutput.length tmp_buf);
  POutput.add_output buf tmp_buf



(* Sequence/Set of *)

(* TODO: min/max *)
let extract_der_seqof header_constraint (* min max *) name parse_content input =
  let rec parse_aux accu input =
    if eos input
    then List.rev accu
    else
      let next = parse_content input in
      parse_aux (next::accu) input
  in extract_der_object header_constraint name (parse_aux []) input

let produce_der_seqof hdr dump_content buf l =
  let dump_der_list_aux b l = List.iter (dump_content b) l in
  produce_der_object hdr dump_der_list_aux buf l
