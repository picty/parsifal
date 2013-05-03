open Parsifal
open BasePTypes
open PTypes
open Asn1Engine
open Lwt

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

let dump_der_boolean_content buf = function
  | true -> Buffer.add_char buf '\xff'
  | false -> Buffer.add_char buf '\x00'

let value_of_der_boolean_content b = VBool b

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

let dump_der_integer_content buf s = Buffer.add_string buf s

let value_of_der_integer_content i = VBigInt (i, BigEndian)

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

let dump_der_smallint_content buf i =
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
  Buffer.add_string buf res

let value_of_der_smallint_content i = VSimpleInt i

asn1_alias der_smallint = primitive [T_Integer] der_smallint_content


(* Null *)

type der_null_content = unit

let parse_der_null_content input =
  if not (eos input)
  then begin
    warning NullNotInNormalForm input;
    drop_rem_bytes input;
  end

let dump_der_null_content _buf () = ()

let value_of_der_null_content () = VUnit

asn1_alias der_null = primitive [T_Null] der_null_content


(* OId *)

type der_oid_content = int list

let (oid_directory : (int list, string) Hashtbl.t) = Hashtbl.create 100
let (rev_oid_directory : (string, int list) Hashtbl.t) = Hashtbl.create 200
let (oid_short_directory : (int list, string) Hashtbl.t) = Hashtbl.create 20

let resolve_oids = ref true


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
	warning_h input.err_fun OIdNotInNormalForm h;
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

let dump_der_oid_content buf idlist =
  let cll = List.map subid_to_charlist idlist in
  let add_char c = Buffer.add_char buf (char_of_int c) in
  List.iter (List.iter add_char) cll


let oid_expand = function
  | [] -> []
  | x::r ->
    let a, b = if x >= 80
      then 2, (x - 80)
      else (x / 40), (x mod 40)
    in a::b::r

let raw_string_of_oid oid =
  String.concat "." (List.map string_of_int (oid_expand oid))

let register_oid ?short:(short=None) oid s =
  Hashtbl.add oid_directory oid s;
  begin
    match short with
    | None -> ()
    | Some sh -> Hashtbl.add oid_short_directory oid sh
  end;
  Hashtbl.add rev_oid_directory s oid;
  Hashtbl.add rev_oid_directory (raw_string_of_oid oid) oid

let string_of_oid oid =
  if !resolve_oids then
    try Hashtbl.find oid_directory oid
    with Not_found -> raw_string_of_oid oid
  else raw_string_of_oid oid
    
let short_string_of_oid oid =
  if !resolve_oids then
    try Hashtbl.find oid_short_directory oid
    with Not_found -> string_of_oid oid
  else raw_string_of_oid oid

let string_of_der_oid_content oid =
  if !resolve_oids then
    try (Hashtbl.find oid_directory oid) ^ " (" ^ raw_string_of_oid oid ^ ")"
    with Not_found -> raw_string_of_oid oid
  else raw_string_of_oid oid

let value_of_der_oid_content oid =
  VRecord [
    "@name", VString ("oid", false);
    "@string_of", VString (string_of_der_oid_content oid, false);
    "oid", VList (List.map (fun x -> VSimpleInt x) (oid_expand oid))
  ]

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

let dump_der_bitstring_content buf (nBits, s) =
  Buffer.add_char buf (char_of_int nBits);
  Buffer.add_string buf s

let value_of_der_bitstring_content (nBits, s) =
  VRecord [
    "@name", VString ("bitstring", false);
    "@string_of", VString (Printf.sprintf "[%d] %s" nBits s, false);
    "nBits", VSimpleInt nBits;
    "content", VString (s, true)
  ]

asn1_alias der_bitstring = primitive [T_BitString] der_bitstring_content



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
  let (_, content) = parse_der_bitstring_content input in
  let values = extract_bit_list content in
  let n = Array.length description in
  let rec aux i = function
    | [] -> []
    | true::_ when i >= n ->
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

let dump_der_enumerated_bitstring_content description buf l =
  let next_val v = ((v lsr 1) lor (v lsl 7)) land 0xff in
  let n = Array.length description in
  let rec enumerate_bits bitval accu i = function
    | [] -> List.rev accu
    | (v_v::r_v as l_v) ->
      if i < n then begin
	let next_bv = next_val bitval in
	if description.(i) = v_v
	then enumerate_bits next_bv (bitval::accu) (i+1) r_v
	else enumerate_bits next_bv (0::accu) (i+1) l_v
      end else begin
	warning_h prerr_endline (BitStringNotInNormalForm "Ignoring unknown strings in the given list") [];
	List.rev accu
      end
  in
  let rec encode accu = function
    | [] -> 0, (List.rev accu)
    | a::b::c::d::e::f::g::h::r -> encode ((a+b+c+d+e+f+g+h)::accu) r
    | l ->
      let nBits = 8 - (List.length l)
      and last_int = (List.fold_left (+) 0 l) in
      nBits, (List.rev (last_int::accu))
  in
  let bits = enumerate_bits 0x80 [] 0 l in
  let nBits, intlist = encode [] bits in
  Buffer.add_char buf (char_of_int nBits);
  let add_char c = Buffer.add_char buf (char_of_int c) in
  List.iter add_char intlist

let value_of_der_enumerated_bitstring_content l =
  VRecord [
    "@name", VString ("der_enumerated_bitstring_content", false);
    "@string_of", VString ("[" ^ (String.concat ", " l) ^ "]", false);
    "content", VList (List.map value_of_string l)
  ]

asn1_alias der_enumerated_bitstring [both_param description] = primitive [T_BitString] der_enumerated_bitstring_content[description]



(* Octet String *)

type der_octetstring_content = string

let no_constraint s _ = s

(* TODO: Cleanup this *)

let parse_der_octetstring_content apply_constraints input =
  let res = parse_rem_string input in
  ignore (apply_constraints res input);
  res

let dump_der_octetstring_content buf s = Buffer.add_string buf s
let value_of_der_octetstring_content s = VString (s, true)
asn1_alias der_octetstring = primitive [T_OctetString] der_octetstring_content(no_constraint)


alias der_printable_octetstring_content [param constr] = der_octetstring_content(constr)
let value_of_der_printable_octetstring_content s = VString (s, false)


(* Time types *)

type time_content = {
  year : int; month : int; day : int;
  hour : int; minute : int; second : int;
}

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
      { year = y; month = m; day = d;
	hour = hh; minute = mm; second = ss }
    end else fatal_error InvalidUTCTime input
  with _ -> fatal_error InvalidUTCTime input

let utc_time_constraint = time_constraint utc_time_re
let generalized_time_constraint = time_constraint generalized_time_re

let utc_year_of_int i = i mod 100
(* TODO: check if it is > or >= *)
let int_of_utc_year y = if y >= 50 then y + 1900 else y + 2000

let string_of_time_content t =
  Printf.sprintf "%4.4d-%2.2d-%2.2d %2.2d:%2.2d:%2.2d UTC"
    t.year t.month t.day t.hour t.minute t.second
let value_of_time_content name t =
  VRecord [
    "@name", VString (name, false);
    "@string_of", VString (string_of_time_content t, false);
    "year", VSimpleInt t.year; "month", VSimpleInt t.month;
    "day", VSimpleInt t.day; "hour", VSimpleInt t.hour;
    "minute", VSimpleInt t.minute; "second", VSimpleInt t.second
  ]
   

type der_utc_time_content = time_content
let parse_der_utc_time_content input =
  let res = parse_rem_string input in
  let tmp = utc_time_constraint res input in
  { tmp with year = int_of_utc_year tmp.year }
let dump_der_utc_time_content buf t =
  Printf.bprintf buf "%2.2d%2.2d%2.2d%2.2d%2.2d%2.2dZ"
    (utc_year_of_int t.year) t.month t.day t.hour t.minute t.second
let value_of_der_utc_time_content t = value_of_time_content "utc_time" t

type der_generalized_time_content = time_content
let parse_der_generalized_time_content input =
  let res = parse_rem_string input in
  generalized_time_constraint res input
let dump_der_generalized_time_content buf t =
  Printf.bprintf buf "%4.4d%2.2d%2.2d%2.2d%2.2d%2.2dZ"
    t.year t.month t.day t.hour t.minute t.second
let value_of_der_generalized_time_content t = value_of_time_content "generalized_time" t


(* Generic ASN.1 Object *)

type der_object = {
  a_class : asn1_class;
  a_tag : asn1_tag;
  a_content : der_object_content;
}

and der_object_content =
  | Boolean of bool
  | Integer of string
  | BitString of int * string
(*  | EnumeratedBitString of (int list) * bitstring_description *)
  | Null
  | OId of int list
  | String of (string * bool)       (* bool : isBinary *)
  | Constructed of der_object list
  | UnparsedDER of (bool * string)  (* bool : constructed *)


let mk_object c t content = {
  a_class = c;
  a_tag = t;
  a_content = content;
}

let isConstructed o = match o.a_content with
  | Constructed _
  | UnparsedDER (true, _) -> true
  | _ -> false


let rec parse_der_object input =
(*   let _offset = input.cur_base + input.cur_offset in *)
(*  let old_cur_offset = input.cur_offset in *)
  let (c, isC, t) = extract_der_header input in
  let len = extract_der_length input in
(*   let _hlen = input.cur_offset - old_cur_offset in *)
  let new_input = get_in input (print_header (c, isC, t)) len in
  let content =
    if input.enrich <> NeverEnrich
    then parse_der_object_content (c, isC, t) new_input
    else UnparsedDER (isC, parse_rem_string new_input)
 in
  get_out input new_input;
  mk_object c t content

and lwt_parse_der_object input =
  lwt_extract_der_header input >>= fun (c, isC, t) ->
  lwt_extract_der_length input >>= fun len ->
  lwt_get_in input (print_header (c, isC, t)) len >>= fun new_input ->
  let content =
    if input.lwt_enrich <> NeverEnrich
    then parse_der_object_content (c, isC, t) new_input
    else UnparsedDER (isC, parse_rem_string new_input)
  in
  lwt_get_out input new_input >>= fun () ->
  return (mk_object c t content)

and parse_der_object_content h input = match h with
  | (C_Universal, false, T_Boolean) -> Boolean (parse_der_boolean_content input)
  | (C_Universal, false, T_Integer) -> Integer (parse_der_integer_content input)
  | (C_Universal, false, T_EndOfContents)
  | (C_Universal, false, T_Null) -> parse_der_null_content input; Null
  | (C_Universal, false, T_OId) -> OId (parse_der_oid_content input)
  | (C_Universal, false, T_BitString) -> let nBits, s = parse_der_bitstring_content input in BitString (nBits, s)
  | (C_Universal, false, T_OctetString) -> String (parse_der_octetstring_content no_constraint input, true)

  | (C_Universal, false, T_UTF8String)
  | (C_Universal, false, T_NumericString)
  | (C_Universal, false, T_PrintableString)
  | (C_Universal, false, T_T61String)
  | (C_Universal, false, T_VideoString)
  | (C_Universal, false, T_IA5String) -> String (parse_der_octetstring_content no_constraint input, false) (* TODO *)
  | (C_Universal, false, T_UTCTime) -> String (parse_der_octetstring_content utc_time_constraint input, false)
  | (C_Universal, false, T_GeneralizedTime) -> String (parse_der_octetstring_content generalized_time_constraint input, false)
  | (C_Universal, false, T_GraphicString)
  | (C_Universal, false, T_VisibleString)
  | (C_Universal, false, T_GeneralString)
  | (C_Universal, false, T_UniversalString)
  | (C_Universal, false, T_UnspecifiedCharacterString)
  | (C_Universal, false, T_BMPString) -> String (parse_der_octetstring_content no_constraint input, false) (* TODO *)

  | (C_Universal, false, T_ObjectDescriptor)
  | (C_Universal, false, T_External)
  | (C_Universal, false, T_Real)
  | (C_Universal, false, T_Enumerated)
  | (C_Universal, false, T_EmbeddedPDV)
  | (C_Universal, false, T_RelativeOId) -> String (parse_rem_string input, true) (* TODO *)

  | (C_Universal, true, T_Sequence)
  | (C_Universal, true, T_Set) -> Constructed (parse_der_constructed_content input)

  | (C_Universal, false, ((T_Set | T_Sequence | T_Unknown _) as t) ) ->
    warning (UnknownUniversalObject (false, t)) input;
    String (parse_der_octetstring_content no_constraint input, true)

  | (C_Universal, true, t) ->
    warning (UnknownUniversalObject (true, t)) input;
    Constructed (parse_der_constructed_content input)

  | (_, false, _) -> String (parse_der_octetstring_content no_constraint input, true)
  | (_, true, _)  -> Constructed (parse_der_constructed_content input)

and parse_der_constructed_content input =
  let rec parse_aux accu =
    if eos input
    then List.rev accu
    else
      let next = parse_der_object input in
      parse_aux (next::accu)
  in parse_aux []


let rec dump_der_object buf o =
  produce_der_object (o.a_class, (isConstructed o), o.a_tag) dump_der_object_content buf o.a_content

and dump_der_object_content buf = function
  | Boolean b -> dump_der_boolean_content buf b
  | Integer i -> dump_der_integer_content buf i
  | BitString (nBits, s) -> dump_der_bitstring_content buf (nBits, s)
  | Null -> dump_der_null_content buf ()
  | OId oid -> dump_der_oid_content buf oid
  | String (s, _) -> dump_der_octetstring_content buf s
  | Constructed l ->
    List.iter (dump_der_object buf) l
  | UnparsedDER (_, s) -> Buffer.add_string buf s


let string_of_der_object_content _ = "der_object"
let string_of_der_object _ = "der_object"

let rec value_of_der_object o =
  let value_of_content = value_of_der_object_content o.a_content in
  VRecord [
    "@name", VString ("asn1_object", false);
    "asn1_header", VString (print_header (o.a_class, isConstructed o, o.a_tag), false);
    "@class", value_of_asn1_class o.a_class;
    "@isConstructed", VBool (isConstructed o);
    "@tag", value_of_asn1_tag o.a_tag;
    "asn1_content", value_of_content
  ]
and value_of_der_object_content = function
  | Boolean b -> value_of_der_boolean_content b
  | Integer i -> value_of_der_integer_content i
  | BitString (nBits, s) -> value_of_der_bitstring_content (nBits, s)
  | Null -> VUnit
  | OId oid -> value_of_der_oid_content oid
  | String (s, binary) -> VString (s, binary)
  | Constructed l -> value_of_list value_of_der_object l
  | UnparsedDER (_, s) -> VString (s, true)


(* ASN.1 Containers *)

type 'a asn1 = 'a
let parse_asn1 h = extract_der_object (print_header h) h
let dump_asn1 = produce_der_object
let value_of_asn1 = value_of_container


type 'a bitstring_container = 'a

let parse_bitstring_container parse_fun input =
  let (_nbits, content) = parse_der_bitstring input in
  (* TODO:    if nbits <> 0 then *)
  let new_input = get_in_container input "bitstring_container" content in
  let res = parse_fun new_input in
  check_empty_input true new_input;
  res

let dump_bitstring_container dump_fun buf o =
  let dump_content_aux b c =
    Buffer.add_char b '\x00';
    dump_fun b c
  in
  produce_der_object (C_Universal, false, T_BitString) dump_content_aux buf o

let value_of_bitstring_container = value_of_container


type 'a octetstring_container = 'a

let parse_octetstring_container parse_fun input =
  let content = parse_der_octetstring input in
  let new_input = get_in_container input "bitstring_container" content in
  let res = parse_fun new_input in
  check_empty_input true new_input;
  res

let dump_octetstring_container dump_fun buf o =
  produce_der_object (C_Universal, false, T_OctetString) dump_fun buf o

let value_of_octetstring_container = value_of_container


let advanced_der_parse (parse_fun : (asn1_class * bool * asn1_tag) -> string_input -> 'a) (input : string_input) : 'a =
  let hdr = extract_der_header input in
  let len = extract_der_length input in
  let new_input = get_in input (print_header hdr) len in
  let res = parse_fun hdr new_input in
  get_out input new_input;
  res

let lwt_advanced_der_parse (parse_fun : (asn1_class * bool * asn1_tag) -> string_input -> 'a) (input : lwt_input) : 'a Lwt.t =
  lwt_extract_der_header input >>= fun hdr ->
  lwt_extract_der_length input >>= fun len ->
  lwt_get_in input (print_header hdr) len >>= fun new_input ->
  let res = parse_fun hdr new_input in
  lwt_get_out input new_input >>= fun () ->
  return res



(* Useful aliases *)
(* TODO: Constraints! *)
asn1_alias der_ia5string [param len_cons] = primitive [T_IA5String]
      length_constrained_container (len_cons) of der_printable_octetstring_content(no_constraint)
asn1_alias der_printablestring [param len_cons] = primitive [T_PrintableString]
      length_constrained_container (len_cons) of  der_printable_octetstring_content(no_constraint)
