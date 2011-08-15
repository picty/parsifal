(* ASN.1 Parsing primitives *)


(* Types *)

type asn1_class =
  | C_Universal
  | C_Application
  | C_ContextSpecific
  | C_Private
      
let class_map = [| C_Universal; C_Application;
		   C_ContextSpecific; C_Private |]
  
type asn1_universal_tag =
  | T_EndOfContents
  | T_Boolean
  | T_Integer
  | T_BitString
  | T_OctetString
  | T_Null
  | T_OId
  | T_ObjectDescriptor
  | T_External
  | T_Real
  | T_Enumerated
  | T_EmbeddedPDV
  | T_UTF8String
  | T_RelativeOId
  | T_Sequence
  | T_Set
  | T_NumericString
  | T_PrintableString
  | T_T61String
  | T_VideoString
  | T_IA5String
  | T_UTCTime
  | T_GeneralizedTime
  | T_GraphicString
  | T_VisibleString
  | T_GeneralString
  | T_UniversalString
  | T_UnspecifiedCharacterString
  | T_BMPString
  | T_Unknown
      
let universal_tag_map =
  [| T_EndOfContents; T_Boolean; T_Integer; T_BitString; T_OctetString;
     T_Null; T_OId; T_ObjectDescriptor; T_External; T_Real;
     T_Enumerated; T_EmbeddedPDV; T_UTF8String; T_RelativeOId; T_Unknown;
     T_Unknown; T_Sequence; T_Set; T_NumericString; T_PrintableString;
     T_T61String; T_VideoString; T_IA5String; T_UTCTime; T_GeneralizedTime;
     T_GraphicString; T_VisibleString; T_GeneralString; T_UniversalString;
     T_UnspecifiedCharacterString; T_BMPString |]
    
type asn1_object = asn1_class * int * asn1_content 
and asn1_content =
  | EndOfContents
  | Boolean of bool
  | Integer of Big_int.big_int
  | BitString of int * string
  | Null
  | OId of int list
  | String of string
  | Constructed of asn1_object list
  | Unknown of string
      
(* Trivial useful functions *)
      
let intlist_of_string s =
  let rec aux accu offset = function
    | 0 -> List.rev accu
    | n -> aux ((int_of_char (String.get s offset))::accu) (offset + 1) (n - 1)
  in
  aux [] 0 (String.length s)
    
let bigint_of_intlist l =
  let rec aux accu = function
    | [] -> accu
    | d::r -> aux (Big_int.add_int_big_int d (Big_int.mult_int_big_int 256 accu)) r
  in aux Big_int.zero_big_int l
  
let string_of_charlist il =
  let res = String.create (List.length il) in
  let rec aux offset l =
    match l with
      | [] -> res
      | i::r ->
	String.set res offset i;
	aux (offset + 1) r
  in aux 0 il
  
(* Trivial parsing functions *)
  
let extract_class (x : int) : asn1_class =
  let i = x lsr 6 in
  class_map.(i)
    
let extract_isConstructed (x : int) : bool =
  let i = (x lsr 5) land 1 in
  i = 1
      
let extract_shorttype (x : int) : int =
  x land 31
    
let extract_longtype (str : string) (offset : int) : int * int =
  (* str is the complete string, with one char to skip *)
  failwith "Long type not implemented"
    
let extract_header (str : string) (offset : int) : ((asn1_class * bool * int) * int) =
  let hdr = int_of_char (String.get str offset) in
  let c = extract_class hdr in
  let isC = extract_isConstructed hdr in
  let t = extract_shorttype hdr in
  if (t < 0x1f)
  then ((c, isC, t), offset + 1)
  else
    let (longT, new_offset) = extract_longtype str offset in
    ((c, isC, longT), new_offset)
      
let extract_length (str : string) (offset : int) : (int * int) =
  let first = int_of_char (String.get str offset) in
  if first land 0x80 = 0
  then (first, offset + 1)
  else
    let lenlen = first land 0x7f in
    let rec aux accu offset = function
      | 0 -> (accu, offset)
      | n -> aux ((accu lsl 8) lor (int_of_char (String.get str offset))) (offset + 1) (n-1)
    in (aux 0 (offset + 1) lenlen)
    
let string_of_header c isC t =
  let cstr = match c with
    | C_Universal -> "[UNIVERSAL "
    | C_Private -> "[PRIVATE "
    | C_Application -> "[APPLICATION "
    | C_ContextSpecific -> "[CONTEXT SPE "
  in
  let isCstr = if isC then "] (cons)" else "] (prim)" in
  cstr ^ (string_of_int t) ^ isCstr
    
let der_to_subid str offset =
  let rec aux accu o =
    let c = int_of_char (String.get str o) in
    let new_accu = (accu lsl 7) lor (c land 0x7f) in
    if c land 0x80 != 0
    then aux new_accu (o+1)
    else (new_accu, o+1)
  in aux 0 offset
  
(* Generic ASN.1 parsing function *)
  
type parse_function = string -> int -> int -> int -> asn1_content
    
let der_to_boolean str base offset len =
  if len <> 1
  then failwith ("Incorrect boolean length" ^ (string_of_int (base + offset)));
  let v = int_of_char (String.get str offset) in
  if v = 0 then Boolean false
  else if v = 255 then Boolean true
  else failwith ("Incorrect boolean value at offset " ^ (string_of_int (base + offset)))

let der_to_int str base offset len =
  if len <= 0
  then failwith ("Incorrect integer length" ^ (string_of_int (base + offset)));
  let l = intlist_of_string (String.sub str offset len) in
  let negative = match l with
    | [] -> failwith ("Incorrect integer length" ^ (string_of_int (base + offset)))
    | x::y::r when x = 0xff -> failwith ("Integer not in normal form" ^ (string_of_int (base + offset)))
    | x::y::r when (x = 0) && (y land 0x80) = 0 -> failwith ("Integer not in normal form" ^ (string_of_int (base + offset)))
    | x::r -> (x land 0x80) = 0x80
  in
  if negative then failwith ("Negative integer not implemented yet" ^ (string_of_int (base + offset)));
  Integer (bigint_of_intlist l)
    
let der_to_null str base offset len =
  if len <> 0
  then failwith ("Incorrect null length" ^ (string_of_int (base + offset)));
  Null
    
let der_to_oid str _ offset len =
  let rec aux o =
    if o - offset = len
    then []
    else
      let (next, new_offset) = der_to_subid str o in
      next::(aux new_offset)
  in
  OId (aux offset)
    
let der_to_bitstring str _ offset len =
  BitString (int_of_char (String.get str offset), String.sub str (offset + 1) (len - 1))
    
let der_to_octetstring str _ offset len =
  String (String.sub str offset len)
    
let der_to_unknown str _ offset len =
  Unknown (String.sub str offset len)
    
let rec der_to_constructed str base offset len =
  let substring = String.sub str offset len in
  let new_base = base + offset in
    
  let rec parse_aux offset =
    if offset = len
    then []
    else 
      let (next, new_offset) = parse substring new_base offset in
      next::(parse_aux new_offset)
  in
  Constructed (parse_aux 0)
    
and choose_parse_fun (c : asn1_class) (isC : bool) (t : int) : parse_function =
  match c with
    | C_Universal when t >= 0 && t < Array.length universal_tag_map -> begin
      match (universal_tag_map.(t), isC) with
	| (T_Boolean, false) -> der_to_boolean
	| (T_Integer, false) -> der_to_int
	  
	| (T_EndOfContents, false)
	| (T_Null, false) -> der_to_null
	  
	| ( T_OId, false) -> der_to_oid
	  
	| (T_BitString, false) -> der_to_bitstring
	  
	| ( T_OctetString, false)
	| ( T_UTF8String, false)
	| ( T_NumericString, false)
	| ( T_PrintableString, false)
	| ( T_T61String, false)
	| ( T_VideoString, false)
	| ( T_IA5String, false)
	| ( T_UTCTime, false)
	| ( T_GeneralizedTime, false)
	| ( T_GraphicString, false)
	| ( T_VisibleString, false)
	| ( T_GeneralString, false)
	| ( T_UniversalString, false)
	| ( T_UnspecifiedCharacterString, false)
	| ( T_BMPString, false) -> der_to_octetstring
	  
	| (T_Sequence, true)
	| (T_Set, true)
	  -> der_to_constructed
	  
	| (T_Unknown, _) -> failwith "Invalid type for Universal class"
	  
	| (_, true) -> failwith "Invalid constructed type"
	  
	| _ -> failwith ("parse: case not implemented: " ^ (string_of_int t))
    end
      
    | C_Universal -> failwith "Invalid type for Universal class"
    | _ when isC -> der_to_constructed
    | _ -> der_to_unknown
      
and parse str base offset : asn1_object * int =
  let ((c, isC, t), o1) = extract_header str offset in
  let (len, o2) = extract_length str o1 in
  let parse_fun = choose_parse_fun c isC t in
  ((c, t, parse_fun str base o2 len), o2 + len)

let exact_parse str : asn1_object =
  let (res, o) = parse str 0 0 in
  if (String.length str) == o
  then res
  else failwith "Trailing bytes at the end of the string"
    
(* DER export functions *)
    
let boolean_to_der b =
  if b then "\xff" else "\x00"
    
let int_to_der i =
  failwith "Not implemented yet"
    
let null_to_der = ""
  
let subid_to_charlist id =
  let rec aux x =
    let q = x lsr 7 in
    let c = char_of_int (x land 0x7f) in
    match q with
      | 0 -> [c]
      | _ -> c::(aux q)
  in aux id
  
let oid_to_der idlist =
  let cll = List.map subid_to_charlist idlist in
  string_of_charlist (List.flatten cll)
    
let bitstring_to_der nBits s =
  let prefix = String.make 1 (char_of_int nBits) in
  prefix ^ s
    
let dump_class c =
  match c with
    | C_Universal -> 0
    | C_Private -> 0x40
    | C_Application -> 0x80
    | C_ContextSpecific -> 0xc0
      
let dump_isConstructed isC =
  if isC then 0x20 else 0
    
let dump_longtype t =
  failwith "Long type not implemented"
    
let dump_header (c : asn1_class) (isC : bool) (t : int) : string =
  let t' = if t < 0x1f then t else 0x1f in
  let h = (dump_class c) lor (dump_isConstructed isC) lor t' in
  let res = String.make 1 (char_of_int h) in
  if t' = 0x1f
  then res ^ dump_longtype t
  else res
    
let dump_length l =
  let rec aux accu lg = match lg with
    | 0 -> accu
    | _ -> aux ((char_of_int (lg land 0xff))::accu) (lg lsr 8)
  in
  
  if l < 0x80
  then String.make 1 (char_of_int l)
  else begin
    let x = aux [] l in
    let prefix = char_of_int ((List.length x) lor 0x80) in
    string_of_charlist (prefix::x)
  end
    
let rec dump (c, t, o) =
  let isC, contents = match o with
    | EndOfContents | Null -> false, null_to_der
    | Boolean b -> false, boolean_to_der b
    | Integer i -> false, int_to_der i
    | BitString (nb, s) -> false, bitstring_to_der nb s
    | OId id -> false, oid_to_der id
    | String s | Unknown s -> false, s
    | Constructed objects -> true, constructed_to_der objects
  in
  let hdr = dump_header c isC t in
  let lg = dump_length (String.length contents) in
  hdr ^ lg ^ contents
    
and constructed_to_der objlist =
  let subdumps = List.map dump objlist in
  String.concat "" subdumps
    
    
(* Useful functions *)
    
let decapsulate = function
  | (_, _, Constructed l) -> l
  | _ -> failwith "Cannot decapsulate a primitive type"
    
let encapsulate c t l =
  (c, t, Constructed l)
      

