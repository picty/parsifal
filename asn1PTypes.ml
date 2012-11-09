open Parsifal
open Asn1Engine

(* Boolean *)

type der_boolean_content = bool

let parse_der_boolean_content input =
  let value = parse_rem_list parse_uint8 input in
  match value with
    | [] ->
      warning BooleanNotInNormalForm input;
      false
    | [0] -> false
    | [255] -> true
    | v::_ ->
      warning BooleanNotInNormalForm input;
      (v <> 0)

let dump_der_boolean_content = function
  | true -> String.make 1 '\xff'
  | false -> String.make 1 '\x00'

let print_der_boolean_content ?indent:(indent="") ?name:(name="der_boolean") v =
  Printf.sprintf "%s%s: %s\n" indent name (string_of_bool v)

asn1_alias der_boolean = primitive [T_Boolean] der_boolean_content


(* Integer *)

type der_integer_content = string

let parse_der_integer_content input =
  let l = parse_rem_string input in
  let two_first_chars =
    let n = String.length l in
    if n = 0 then []
    else if n = 1 then [int_of_char l.[0]]
    else [int_of_char l.[0] ; int_of_char l.[1]]
  in
  begin
    match two_first_chars with
      | [] -> warning IntegerNotInNormalForm input
      | x::y::_ ->
	if (x = 0xff) || ((x = 0) && (y land 0x80) = 0)
	then warning IntegerNotInNormalForm input
      | _ -> ()
  end;
  l

let dump_der_integer_content s = s

let print_der_integer_content ?indent:(indent="") ?name:(name="der_integer") v =
  Printf.sprintf "%s%s: %s\n" indent name (hexdump v)

asn1_alias der_integer = primitive [T_Integer] der_integer_content


type der_smallint_content = int

let parse_der_smallint_content input =
  let integer_s = parse_der_integer_content input in
  let len = String.length integer_s in
  if (len > 0 && (int_of_char (integer_s.[0]) land 0x80) = 0x80) || (len > 4)
  then fatal_error IntegerOverflow input
  else begin
    let rec int_of_binstr accu i =
      if i >= len
      then accu
      else int_of_binstr ((accu lsl 8) + (int_of_char integer_s.[i])) (i+1)
    in int_of_binstr 0 0
  end

let dump_der_smallint_content i =
  let rec compute_size rem =
    if rem < 0x80 then 1
    else if rem < 0x100 then 2
    else 1 + (compute_size (rem lsr 8))
  in
  let sz = compute_size i in
  let res = String.make sz '\x00' in
  let rec mk_content where rem =
    if rem = 0 then ()
    else begin
      res.[where] <- char_of_int (rem land 0xff);
      mk_content (where - 1) (rem lsr 8)
    end
  in
  mk_content (sz-1) i;
  res

let print_der_smallint_content ?indent:(indent="") ?name:(name="der_smallint") v =
  Printf.sprintf "%s%s: %d (%4.4x)\n" indent name v v

asn1_alias der_smallint = primitive [T_Integer] der_smallint_content


(* Null *)

type der_null_content = unit

let parse_der_null_content input =
  if not (eos input)
  then begin
    warning NullNotInNormalForm input;
    drop_rem_bytes input;
  end

let dump_der_null_content () = ""

let print_der_null_content ?indent:(indent="") ?name:(name="der_null_content") () =
  Printf.sprintf "%s%s\n" indent name

asn1_alias der_null = primitive [T_Null] der_null_content


(* OId *)

type der_oid_content = int list

let parse_subid input : int =
  let rec aux accu =
    let c = parse_uint8 input in
    let new_accu = (accu lsl 7) lor (c land 0x7f) in
    if c land 0x80 != 0
    then aux new_accu
    else new_accu
  in aux 0

let parse_der_oid_content input =
  let rec aux () =
    if eos input
    then []
    else begin
      try
	let next = parse_subid input in
	next::(aux ())
      with ParsingException (OutOfBounds, h) ->
	warning_h OIdNotInNormalForm h;
	[]
    end
  in
  aux ()

let subid_to_charlist id =
  let rec aux accu x =
    if x = 0
    then accu
    else aux (((x land 0x7f) lor 0x80)::accu) (x lsr 7)
  in aux [id land 0x7f] (id lsr 7)

let _string_of_int_list l =
  let len = List.length l in
  let res = String.make len ' ' in
  let rec populate_string i = function
    | [] -> res
    | c::r ->
      res.[i] <- char_of_int c;
      populate_string (i+1) r
  in populate_string 0 l

let dump_der_oid_content idlist =
  let cll = List.map subid_to_charlist idlist in
  _string_of_int_list (List.flatten cll)


let oid_expand = function
  | [] -> []
  | x::r ->
    let a, b = if x >= 80
      then 2, (x - 80)
      else (x / 40), (x mod 40)
    in a::b::r

let raw_string_of_oid oid =
  String.concat "." (List.map string_of_int (oid_expand oid))

let register_oid oid s =
  Hashtbl.add oid_directory oid s;
  Hashtbl.add rev_oid_directory s oid;
  Hashtbl.add rev_oid_directory (raw_string_of_oid oid) oid

let print_der_oid_content ?indent:(indent="") ?name:(name="der_oid_content") oid =
  let value = if !resolve_oids then
      try (Hashtbl.find oid_directory oid) ^ " (" ^ raw_string_of_oid oid ^ ")"
      with Not_found -> raw_string_of_oid oid
    else raw_string_of_oid oid
  in
  Printf.sprintf "%s%s: %s\n" indent name (value)

asn1_alias der_oid = primitive [T_OId] der_oid_content



(* Bit String *)

type der_bitstring_content = int * string

let parse_der_bitstring_content input =
  let nBits =
    if eos input then begin
      warning (BitStringNotInNormalForm "empty") input;
      0
    end else parse_uint8 input
  in
  let content = parse_rem_string input in
  let len = (String.length content) * 8 - nBits in
  if len < 0
  then warning (BitStringNotInNormalForm "invalid length") input;
  (* TODO: Check the trailing bits are zeroed. *)
  (nBits, content)

let dump_der_bitstring_content (nBits, s) =
  let prefix = String.make 1 (char_of_int nBits) in
  prefix ^ s

let print_der_bitstring_content ?indent:(indent="") ?name:(name="der_bitstring_content") (nBits, s) =
  Printf.sprintf "%s%s: [%d] %s\n" indent name nBits (hexdump s)

asn1_alias der_bitstring = primitive [T_BitString] der_bitstring_content



(* TODO: Should this really be a string list? *)
type der_enumerated_bitstring_content = string list

let extract_bit_list s =
  let n = String.length s in
  let rec extract_from_byte accu i b =
    if i = 0 then accu
    else extract_from_byte (((b land i) <> 0)::accu) (i lsr 1) b
  in
  let rec extract_from_str accu offset =
    if (offset >= n) then List.rev accu
    else extract_from_str (extract_from_byte accu 0x80 (int_of_char s.[offset])) (offset + 1)
  in
  extract_from_str [] 0

let parse_der_enumerated_bitstring_content description input =
  let (nBits, content) = parse_der_bitstring_content input in
  let values = extract_bit_list content in
  let n = Array.length description in
  let rec aux i = function
    | [] -> []
    | true::r when i >= n ->
      warning (BitStringNotInNormalForm "Trailing bits in an enumerated bit string should be null") input;
      []
    | true::r -> (i)::(aux (i+1) r)
    | false::r when i = n ->
      warning (BitStringNotInNormalForm "Only significant bit should be put inside an enumerated bit string") input;
      aux (i+1) r
    | false::r -> aux (i+1) r
  in
  let res = aux 0 values in
  List.map (fun v -> description.(v)) res

(* TODO! *)
let dump_der_enumerated_bitstring_content _description _v =
  raise (ParsingException (NotImplemented "dump_der_enumerated_bistring_content", []))

let print_der_enumerated_bitstring_content ?indent:(indent="") ?name:(name="der_bitstring_content") l =
  Printf.sprintf "%s%s: %s\n" indent name (String.concat ", " l)

asn1_alias der_enumerated_bitstring [both_param description] = primitive [T_BitString] der_enumerated_bitstring_content[description]



(* Octet String *)

type der_octetstring_content = string

let no_constraint s _ = s

let utc_time_re =
  Str.regexp "^\\([0-9][0-9]\\)\\([0-9][0-9]\\)\\([0-9][0-9]\\)\\([0-9][0-9]\\)\\([0-9][0-9]\\)\\([0-9][0-9]\\)Z$"
let generalized_time_re =
  Str.regexp "^\\([0-9][0-9][0-9][0-9]\\)\\([0-9][0-9]\\)\\([0-9][0-9]\\)\\([0-9][0-9]\\)\\([0-9][0-9]\\)\\([0-9][0-9]\\)Z$"

let time_constraint re s input =
  try
    if Str.string_match re s 0 then begin
      let y = int_of_string (Str.matched_group 1 s)
      and m = int_of_string (Str.matched_group 2 s)
      and d = int_of_string (Str.matched_group 3 s)
      and hh = int_of_string (Str.matched_group 4 s)
      and mm = int_of_string (Str.matched_group 5 s)
      and ss = int_of_string (Str.matched_group 6 s) in
      if m = 0 || m > 12 || d = 0 || d > 31 || hh >= 24 || mm > 59 || ss > 59
      then warning InvalidUTCTime input;
      (y, m, d, hh, mm, ss)
    end else fatal_error InvalidUTCTime input
  with _ -> fatal_error InvalidUTCTime input

let utc_time_constraint = time_constraint utc_time_re
let generalized_time_constraint = time_constraint generalized_time_re

(* TODO: Cleanup this *)

let parse_der_processed_string_content apply_constraints input =
  let res = parse_rem_string input in
  apply_constraints res input

let parse_der_octetstring_content apply_constraints input =
  let res = parse_rem_string input in
  ignore (apply_constraints res input);
  res

let dump_der_octetstring_content s = s

let print_der_octetstring_content ?indent:(indent="") ?name:(name="der_octetstring") s =
  Printf.sprintf "%s%s: %s\n" indent name (hexdump s)

asn1_alias der_octetstring = primitive [T_OctetString] der_octetstring_content(no_constraint)




(* Generic ASN.1 Object *)

type der_object = {
  a_class : asn1_class;
  a_tag : asn1_tag;
  a_content : asn1_content;
}

and asn1_content =
  | Boolean of bool
  | Integer of string
  | BitString of int * string
(*  | EnumeratedBitString of (int list) * bitstring_description *)
  | Null
  | OId of int list
  | String of (string * bool)       (* bool : isBinary *)
  | Constructed of der_object list


let mk_object c t content = {
  a_class = c;
  a_tag = t;
  a_content = content;
}

let isConstructed o = match o.a_content with
  | Constructed _ -> true
  | _ -> false


let rec parse_der_object input =
  let _offset = input.cur_base + input.cur_offset in
  let old_cur_offset = input.cur_offset in
  let c, isC, t = extract_der_header input in
  let len = extract_der_length input in
  let _hlen = input.cur_offset - old_cur_offset in
  let new_input = get_in input (print_header (c, isC, t)) len in
  let content = match c, isC, t with
    | (C_Universal, false, T_Boolean) -> Boolean (parse_der_boolean_content new_input)
    | (C_Universal, false, T_Integer) -> Integer (parse_der_integer_content new_input)
    | (C_Universal, false, T_Null) -> parse_der_null_content new_input; Null
    | (C_Universal, false, T_OId) -> OId (parse_der_oid_content new_input)
    | (C_Universal, false, T_BitString) -> let nBits, s = parse_der_bitstring_content new_input in BitString (nBits, s)
    | (C_Universal, false, T_OctetString) -> String (parse_der_octetstring_content no_constraint new_input, true)

    | (C_Universal, false, T_UTF8String)
    | (C_Universal, false, T_NumericString)
    | (C_Universal, false, T_PrintableString)
    | (C_Universal, false, T_T61String)
    | (C_Universal, false, T_VideoString)
    | (C_Universal, false, T_IA5String) -> String (parse_der_octetstring_content no_constraint new_input, false) (* TODO *)
    | (C_Universal, false, T_UTCTime) -> String (parse_der_octetstring_content utc_time_constraint new_input, false)
    | (C_Universal, false, T_GeneralizedTime) -> String (parse_der_octetstring_content generalized_time_constraint new_input, false)
    | (C_Universal, false, T_GraphicString)
    | (C_Universal, false, T_VisibleString)
    | (C_Universal, false, T_GeneralString)
    | (C_Universal, false, T_UniversalString)
    | (C_Universal, false, T_UnspecifiedCharacterString)
    | (C_Universal, false, T_BMPString) -> String (parse_der_octetstring_content no_constraint input, false) (* TODO *)

    | (C_Universal, true, T_Sequence)
    | (C_Universal, true, T_Set) -> Constructed (parse_der_constructed_content new_input)

    | (C_Universal, false, t) ->
      warning (UnknownUniversalObject (false, t)) new_input;
      String (parse_der_octetstring_content no_constraint new_input, true)

    | (C_Universal, true, t) ->
      warning (UnknownUniversalObject (true, t)) new_input;
      Constructed (parse_der_constructed_content new_input)

    | (_, false, _) -> String (parse_der_octetstring_content no_constraint new_input, true)
    | (_, true, _)  -> Constructed (parse_der_constructed_content new_input)
  in
  get_out input new_input;
  mk_object c t content

and parse_der_constructed_content input =
  let rec parse_aux accu =
    if eos input
    then List.rev accu
    else
      let next = parse_der_object input in
      parse_aux (next::accu)
  in parse_aux []


let rec dump_der_object o =
  let hdr = dump_der_header (o.a_class, (isConstructed o), o.a_tag) in
  let content = dump_der_content o.a_content in
  let len = dump_der_length (String.length content) in
  hdr ^ len ^ content

and dump_der_content = function
  | Boolean b -> dump_der_boolean_content b
  | Integer i -> dump_der_integer_content i
  | BitString (nBits, s) -> dump_der_bitstring_content (nBits, s)
  | Null -> dump_der_null_content ()
  | OId oid -> dump_der_oid_content oid
  | String (s, _) -> dump_der_octetstring_content s
  | Constructed l ->
    String.concat "" (List.map dump_der_object l)


let rec print_der_object ?indent:(indent="") ?name:(name="") o =
  let real_name =
    if name = ""
    then print_header (o.a_class, isConstructed o, o.a_tag)
    else name
  in
  print_der_content ~indent:indent ~name:real_name o.a_content

and print_der_content ?indent:(indent="") ?name:(name="der_object") = function
  | Boolean b -> print_der_boolean_content ~indent:indent ~name:name b
  | Integer i -> print_der_integer_content ~indent:indent ~name:name i
  | BitString (nBits, s) -> print_der_bitstring_content ~indent:indent ~name:name (nBits, s)
  | Null -> print_der_null_content ~indent:indent ~name:name ()
  | OId oid -> print_der_oid_content ~indent:indent ~name:name oid
  | String (s, true) -> print_binstring ~indent:indent ~name:name s
  | String (s, false) -> print_printablestring ~indent:indent ~name:name s
  | Constructed l -> print_list print_der_object ~indent:indent ~name:name l



(* ASN.1 Containers *)

let parse_asn1 h = extract_der_object (print_header h) h
let dump_asn1 = produce_der_object


let parse_bitstring_container parse_fun input =
  let (_nbits, content) = parse_der_bitstring input in
  (* TODO:    if nbits <> 0 then *)
  let new_input = {
    (input_of_string "subjectPublicKey_content" content) with
      history = (input.cur_name, input.cur_offset, Some input.cur_length)::input.history;
      enrich = input.enrich
  } in
  let res = parse_fun new_input in
  check_empty_input true new_input;
  res

let dump_bitstring_container dump_fun o =
  let content = dump_fun o in
  dump_der_bitstring (0, content)


let parse_octetstring_container parse_fun input =
  let content = parse_der_octetstring input in
  let new_input = {
    (input_of_string "subjectPublicKey_content" content) with
      history = (input.cur_name, input.cur_offset, Some input.cur_length)::input.history;
      enrich = input.enrich
  } in
  let res = parse_fun new_input in
  check_empty_input true new_input;
  res

let dump_octetstring_container dump_fun o =
  let content = dump_fun o in
  dump_der_octetstring content


(* DER advanced object *)
let advanced_der_parse (parse_fun : (asn1_class * bool * asn1_tag) -> string_input -> 'a) (input : string_input) : 'a =
  let hdr = extract_der_header input in
  let len = extract_der_length input in
  let new_input = get_in input (print_header hdr) len in
  let res = parse_fun hdr new_input in
  get_out input new_input;
  res




(* Useful aliases *)
(* TODO: Constraints! *)
asn1_alias der_ia5string = primitive [T_IA5String] der_octetstring_content(no_constraint)
asn1_alias der_printablestring = primitive [T_PrintableString] der_octetstring_content(no_constraint)
