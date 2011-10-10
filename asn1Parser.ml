module Asn1EngineParams = struct
  type parsing_error =
    | InternalMayhem
    | OutOfBounds of string
    | NotImplemented of string
    | IncorrectLength of string
    | NotInNormalForm of string
    | UnknownUniversal of (bool * int)

  let out_of_bounds_error s = OutOfBounds s

  let string_of_perror = function
    | InternalMayhem -> "Internal mayhem"
    | OutOfBounds s -> "Out of bounds (" ^ s ^ ")"
    | NotImplemented s -> "Not implemented (" ^ s ^  ")"
    | IncorrectLength t -> "Incorrect length for a " ^ t
    | NotInNormalForm t -> t ^ " not in normal form"
    | UnknownUniversal (isC, t) ->
      "Unknown " ^ (if isC then "constructed" else "primitive") ^
	"universal type " ^ (string_of_int t)


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
open Asn1;;
open Engine;;

(* Trivial useful functions *)
(* TODO: Put all this shit inside a correct BigNum implementation *)

let bigint_of_intlist l =
  let rec aux accu = function
    | [] -> accu
    | d::r -> aux (Big_int.add_int_big_int d (Big_int.mult_int_big_int 256 accu)) r
  in aux Big_int.zero_big_int l

(*let string_of_charlist il =
  let res = String.create (List.length il) in
  let rec aux offset l =
    match l with
      | [] -> res
      | i::r ->
	String.set res offset i;
	aux (offset + 1) r
  in aux 0 il*)


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
  raise (ParsingError (NotImplemented "Long type", S_Fatal, pstate))


let extract_header (pstate : parsing_state) : ((asn1_class * bool * int) * parsing_state) =
  let hdr, new_pstate = pop_byte pstate in
  let c = extract_class hdr in
  let isC = extract_isConstructed hdr in
  let t = extract_shorttype hdr in
  if (t < 0x1f)
  then ((c, isC, t), new_pstate)
  else
    let (longT, new_pstate) = extract_longtype new_pstate in
    ((c, isC, longT), new_pstate)

let extract_length (pstate : parsing_state) : (parsing_state * parsing_state) =
  let first, new_pstate = pop_byte pstate in
  if first land 0x80 = 0
  then split_pstate new_pstate first
  else
    let len_pstate = {new_pstate with len = first land 0x7f} in
    let rec aux accu pstate = match pstate.len with
      | 0 -> split_pstate pstate accu
      | n ->
	let x, next_pstate = pop_byte pstate in
	aux ((accu lsl 8) lor x) next_pstate
    in aux 0 len_pstate


let der_to_subid (pstate : parsing_state) : (int * parsing_state) =
  let rec aux accu pstate =
    let c, new_state = pop_byte pstate in
    let new_accu = (accu lsl 7) lor (c land 0x7f) in
    if c land 0x80 != 0
    then aux new_accu new_state
    else new_accu, new_state
  in aux 0 pstate


(* Generic ASN.1 parsing function *)

type parse_function = parsing_state -> asn1_content

let der_to_boolean pstate =
  if pstate.len <> 1 then pstate.ehf (IncorrectLength "bool") S_IdempotenceBreaker pstate;
  if pstate.len = 0 then Boolean false
  else begin
    let v, _ = pop_byte pstate in
    if v = 0 then Boolean false
    else if v = 255 then Boolean true
    else begin
      pstate.ehf (NotInNormalForm "boolean") S_IdempotenceBreaker pstate;
      Boolean false
    end
  end

let der_to_int pstate =
  if pstate.len <= 0 then pstate.ehf (IncorrectLength "integer") S_IdempotenceBreaker pstate;
  let l = get_bytes pstate in
  let negative = match l with
    | [] -> false
    | x::y::r when x = 0xff ->
      pstate.ehf (NotInNormalForm "integer") S_IdempotenceBreaker pstate;
      true
    | x::y::r when (x = 0) && (y land 0x80) = 0 ->
      pstate.ehf (NotInNormalForm "integer") S_IdempotenceBreaker pstate;
      false
    | x::r -> (x land 0x80) = 0x80
  in
  if negative
  then raise (ParsingError (NotImplemented "Negative integer", S_Fatal, pstate))
  else Integer (bigint_of_intlist l)

let der_to_null pstate =
  if pstate.len <> 0 then pstate.ehf (IncorrectLength "null") S_IdempotenceBreaker pstate;
  Null

let der_to_oid pstate =
  let rec aux pstate = match pstate.len with
    | 0 -> []
    | _ ->
      let next, new_pstate = der_to_subid pstate in
      next::(aux new_pstate)
  in
  OId (aux pstate)

let der_to_bitstring _type pstate =
  let nBits, new_pstate = pop_byte pstate in
  let content = get_string new_pstate in
  (* TODO: Checks on nBits and on the final zeros *)
  BitString (nBits, content)

(* TODO: Add constraints *)
(* In particular, wether the octetstring is binary or not *)
let der_to_octetstring _constraints pstate =
  String (get_string pstate, true)

let der_to_unknown pstate =
  Unknown (get_string pstate)


let rec der_to_constructed name pstate =
  let new_pstate = enter_pstate name pstate in
    
  let rec parse_aux pstate = match pstate.len with
    | 0 -> []
    | _ ->
      let (next, new_pstate) = parse pstate in
      next::(parse_aux new_pstate)
  in
  Constructed (parse_aux new_pstate)
    
and choose_parse_fun pstate (c : asn1_class) (isC : bool) (t : int) : parse_function =
  match c with
    | C_Universal when t >= 0 && t < Array.length universal_tag_map -> begin
      match (universal_tag_map.(t), isC) with
	| (T_Boolean, false) -> der_to_boolean
	| (T_Integer, false) -> der_to_int
	  
	| (T_EndOfContents, false)
	| (T_Null, false) -> der_to_null
	  
	| ( T_OId, false) -> der_to_oid
	  
	| (T_BitString, false) -> der_to_bitstring None
	  
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
	| ( T_BMPString, false) -> der_to_octetstring None
	  
	| (T_Sequence, true) -> der_to_constructed "Sequence"
	| (T_Set, true) -> der_to_constructed "Set"
	  
	| (_, false) ->
	  pstate.ehf (UnknownUniversal (false, t)) S_SpecLightlyViolated pstate;
	  der_to_unknown

	| (_, true) ->
	  pstate.ehf (UnknownUniversal (true, t)) S_SpecLightlyViolated pstate;
	  der_to_constructed (string_of_header_raw c true t)
    end
      
    | C_Universal when isC ->
      pstate.ehf (UnknownUniversal (true, t)) S_SpecLightlyViolated pstate;
      der_to_constructed (string_of_header_raw c true t)
    | C_Universal ->
      pstate.ehf (UnknownUniversal (false, t)) S_SpecLightlyViolated pstate;
      der_to_unknown

    | _ when isC -> der_to_constructed (string_of_header_raw c true t)
    | _ -> der_to_unknown
      
and parse pstate : asn1_object * parsing_state =
  let (c, isC, t), hdr_pstate = extract_header pstate in
  let obj_pstate, new_pstate = extract_length hdr_pstate in
  let parse_fun = choose_parse_fun obj_pstate c isC t in
  ({a_class = c; a_tag = t; a_content = parse_fun obj_pstate; a_name = ""}, new_pstate)

let exact_parse ehf orig str : asn1_object =
  let pstate = make_pstate ehf orig str in
  let (res, end_state) = parse pstate in
  if (end_state.len <> 0)
  then failwith "Trailing bytes at the end of the string"
  else res



  
(*

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
      
*)
