module Asn1EngineParams = struct
  type parsing_error =
    | InternalMayhem
    | OutOfBounds
    | NotImplemented of string
    | IncorrectLength of string
    | NotInNormalForm of string
    | UnknownUniversal of int

  let out_of_bounds_error = OutOfBounds

  let string_of_perror = function
    | InternalMayhem -> "Internal mayhem"
    | OutOfBounds -> "Out of bounds"
    | NotImplemented s -> "Not implemented (" ^ s ^  ")"
    | IncorrectLength t -> "Incorrect length for a " ^ t
    | NotInNormalForm t -> t ^ " not in normal form"
    | UnknownUniversal t -> "Unknown universal type " ^ (string_of_int t)


  type severity =
    | S_OK
    | S_Benign
    | S_IdempotenceBreaker
    | S_SpecLightlyViolated
    | S_SpecFatallyViolated
    | S_Fatal

  let fatal_severity = S_Fatal

  let string_of_severity = function
    | S_OK -> "OK"
    | S_Benign -> "Benign"
    | S_IdempotenceBreaker -> "IdempotenceBreaker"
    | S_SpecLightlyViolated -> "SpecLightlyViolated"
    | S_SpecFatallyViolated -> "SpecFatallyViolated"
    | S_Fatal -> "Fatal"

  let int_of_severity = function
    | S_OK -> 0
    | S_Benign -> 1
    | S_IdempotenceBreaker -> 2
    | S_SpecLightlyViolated -> 3
    | S_SpecFatallyViolated -> 4
    | S_Fatal -> 5

  let compare_severity x y =
    compare (int_of_severity x) (int_of_severity y)
end

open Asn1EngineParams;;
module Engine = ParsingEngine.ParsingEngine (Asn1EngineParams);;
(* Trivial useful functions *)
(* TODO: Put all this shit inside a correct BigNum implementation *)

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

let extract_longtype (pstate : parsing_state) : (int * parsing_state) =
  (* str is the complete string, with one char to skip *)
  raise NotImplemented ("Long type", pstate)

let extract_header (pstate : parsing_state) : ((asn1_class * bool * int) * parsing_state) =
  let hdr = cur_byte pstate in
  let c = extract_class hdr in
  let isC = extract_isConstructed hdr in
  let t = extract_shorttype hdr in
  if (t < 0x1f)
  then ((c, isC, t), eat_bytes pstate 1
  else
    let (longT, new_pstate) = extract_longtype pstate in
    ((c, isC, longT), new_pstate)

let extract_length (pstate : parsing_state) : parsing_state =
  let first = cur_byte pstate in
  if first land 0x80 = 0
  then pstate with {offset = pstate.offset + 1; len = first}
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

type parse_function = error_handling_function -> parsing_state -> asn1_content

let der_to_boolean ehf pstate =
  if l <> pstate.len then ehf (IncorrectLength "bool") S_IdempotenceBreaker pstate;
  if pstate.len = 0 then Boolean false
  else begin
    let v = int_of_char (String.get pstate.str offset) in
    if v = 0 then Boolean false
    else if v = 255 then Boolean true
    else begin
      ehf (NotInNormalForm "boolean") S_IdempotenceBreaker pstate;
      Boolean false
    end
  end

let der_to_int ehf pstate =
  if l <> pstate.len then ehf (IncorrectLength "bool") S_IdempotenceBreaker pstate;
  if len <= 0
  then raise ParsingError (IncorrectLength "integer", string_of_int (base + offset));
  let l = intlist_of_string (String.sub str offset len) in
  let negative = match l with
    | [] -> raise ParsingError (IncorrectLength "integer", string_of_int (base + offset));
    | x::y::r when x = 0xff -> raise ParsingError (NotInNormalForm "integer", string_of_int (base + offset))
    | x::y::r when (x = 0) && (y land 0x80) = 0 -> raise ParsingError (NotInNormalForm "integer", string_of_int (base + offset))
    | x::r -> (x land 0x80) = 0x80
  in
  if negative then NotImplemented ("Negative integer", (string_of_int (base + offset));
  Integer (bigint_of_intlist l)

let der_to_null str base offset len =
  if len <> 0
  then raise ParsingError (IncorrectLength "null", string_of_int (base + offset));
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
	  
	| (T_Unknown, _) -> raise ParsingError (UnknownUniversal t,  "Invalid type for Universal class"
	  
	| (_, true) -> raisego "Invalid constructed type"
	  
	| _ -> raisego ("parse: case not implemented: " ^ (string_of_int t))
    end
      
    | C_Universal -> raisego "Invalid type for Universal class"
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
  else raisego "Trailing bytes at the end of the string"
    
(* DER export functions *)
    
let boolean_to_der b =
  if b then "\xff" else "\x00"
    
let int_to_der i =
  raisego "Not implemented yet"
    
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
  raisego "Long type not implemented"
    
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
  | _ -> raisego "Cannot decapsulate a primitive type"
    
let encapsulate c t l =
  (c, t, Constructed l)
      
