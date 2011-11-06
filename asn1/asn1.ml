open Types
open Modules
open Printer
open ParsingEngine



type asn1_errors =
  | NotInNormalForm
  | UnknownPrimitiveUniversal
  | UnknownConstructedUniversal
  | UnexpectedJunk
  | TooFewObjects
  | TooManyObjects
  | UnexpectedHeader
  | InvalidDate

let asn1_errors_strings = [|
  (NotInNormalForm, s_idempotencebreaker, "Object is not in normal form");
  (UnexpectedJunk, s_idempotencebreaker, "Trailing bytes in a parsed objects");

  (UnknownPrimitiveUniversal, s_speclightlyviolated, "Unknown primitive universal type");
  (UnknownConstructedUniversal, s_speclightlyviolated, "Unknown constructed universal type");
  (TooFewObjects, s_speclightlyviolated, "Too few objects");
  (TooManyObjects, s_speclightlyviolated, "Too many objects");
  (UnexpectedHeader, s_speclightlyviolated, "Unexpected header");

  (InvalidDate, s_speclightlyviolated, "Invalid date");
|]

let asn1_emit = register_module_errors_and_make_emit_function "ASN.1" asn1_errors_strings



(*****************)
(* General types *)
(*****************)

type asn1_class =
  | C_Universal
  | C_Application
  | C_ContextSpecific
  | C_Private

let class_map = [| C_Universal; C_Application;
		   C_ContextSpecific; C_Private |]


type asn1_universal_tag =
  | T_EndOfContents               (*  0 *)
  | T_Boolean                     (*  1 *)
  | T_Integer                     (*  2 *)
  | T_BitString                   (*  3 *)
  | T_OctetString                 (*  4 *)
  | T_Null                        (*  5 *)
  | T_OId                         (*  6 *)
  | T_ObjectDescriptor            (*  7 *)
  | T_External                    (*  8 *)
  | T_Real                        (*  9 *)
  | T_Enumerated                  (* 10 *)
  | T_EmbeddedPDV                 (* 11 *)
  | T_UTF8String                  (* 12 *)
  | T_RelativeOId                 (* 13 *)
  | T_Sequence                    (* 16 *)
  | T_Set                         (* 17 *)
  | T_NumericString               (* 18 *)
  | T_PrintableString             (* 19 *)
  | T_T61String                   (* 20 *)
  | T_VideoString                 (* 21 *)
  | T_IA5String                   (* 22 *)
  | T_UTCTime                     (* 23 *)
  | T_GeneralizedTime             (* 24 *)
  | T_GraphicString               (* 25 *)
  | T_VisibleString               (* 26 *)
  | T_GeneralString               (* 27 *)
  | T_UniversalString             (* 28 *)
  | T_UnspecifiedCharacterString  (* 29 *)
  | T_BMPString                   (* 30 *)
  | T_Unknown

let universal_tag_map =
  [| T_EndOfContents; T_Boolean; T_Integer; T_BitString; T_OctetString;
     T_Null; T_OId; T_ObjectDescriptor; T_External; T_Real;
     T_Enumerated; T_EmbeddedPDV; T_UTF8String; T_RelativeOId; T_Unknown;
     T_Unknown; T_Sequence; T_Set; T_NumericString; T_PrintableString;
     T_T61String; T_VideoString; T_IA5String; T_UTCTime; T_GeneralizedTime;
     T_GraphicString; T_VisibleString; T_GeneralString; T_UniversalString;
     T_UnspecifiedCharacterString; T_BMPString |]


type asn1_object = {
  a_class : asn1_class;
  a_tag : int;
  a_ohl : (int * int * int) option;  (* offset, hlen, len *)
  a_content : asn1_content;
  a_name : string;
}

and asn1_content =
  | Boolean of bool
  | Integer of string
  | BitString of int * string
  | Null
  | OId of int list
  | String of (string * bool)       (* bool : isBinary *)
  | Constructed of asn1_object list

let mk_object name c t offset hlen len content =
  {a_class = c; a_tag = t; a_ohl = Some (offset, hlen, len);
   a_content = content; a_name = name}

let mk_object' name c t content =
  {a_class = c; a_tag = t; a_ohl = None;
   a_content = content; a_name = name}


(*****************************)
(* Header printing functions *)
(*****************************)

let string_of_class = function
  | C_Universal -> "Universal"
  | C_Application -> "Application"
  | C_ContextSpecific -> "Context Specific"
  | C_Private -> "Private"

let string_of_universal_tag = function
  | T_EndOfContents -> "EOC"
  | T_Boolean -> "Boolean"
  | T_Integer -> "Integer"
  | T_BitString -> "Bit String"
  | T_OctetString -> "Octet String"
  | T_Null -> "Null"
  | T_OId -> "OId"
  | T_ObjectDescriptor -> "Object Descriptor"
  | T_External -> "External"
  | T_Real -> "Real"
  | T_Enumerated -> "Enumerated"
  | T_EmbeddedPDV -> "EmbeddedPDV"
  | T_UTF8String -> "UTF8 String"
  | T_RelativeOId -> "Relative OId"
  | T_Sequence -> "Sequence"
  | T_Set -> "Set"
  | T_NumericString -> "Numeric String"
  | T_PrintableString -> "Printable String"
  | T_T61String -> "T61 String"
  | T_VideoString -> "Video String"
  | T_IA5String -> "IA5 String"
  | T_UTCTime -> "UTC Time"
  | T_GeneralizedTime -> "Generalized Time"
  | T_GraphicString -> "Graphic String"
  | T_VisibleString -> "Visible String"
  | T_GeneralString -> "General String"
  | T_UniversalString -> "Universal String"
  | T_UnspecifiedCharacterString -> "Unspecified Character String"
  | T_BMPString -> "BMP String"
  | T_Unknown -> "Unknown"

let string_of_tag c t =
  if c = C_Universal && t >= 0 && t < Array.length universal_tag_map
  then begin
    match universal_tag_map.(t) with
      | T_Unknown -> string_of_int t
      | univ_tag -> string_of_universal_tag univ_tag
  end else string_of_int t

let string_of_header_raw c isC t =
  let cstr = match c with
    | C_Universal -> "[UNIVERSAL "
    | C_Private -> "[PRIVATE "
    | C_Application -> "[APPLICATION "
    | C_ContextSpecific -> "[CONTEXT SPE "
  in
  let isCstr = if isC then "] (cons)" else "] (prim)" in
  cstr ^ (string_of_int t) ^ isCstr

let string_of_header_pretty c isC t =
  if c = C_Universal && t >= 0 && t < Array.length universal_tag_map
  then begin
    match universal_tag_map.(t) with
      | T_Unknown -> string_of_header_raw c isC t
      | univ_tag -> string_of_universal_tag univ_tag
  end else string_of_header_raw c isC t  




(*********************)
(* Parsing functions *)
(*********************)

(* Header *)

let extract_class (x : int) : asn1_class =
  let i = x lsr 6 in
  class_map.(i)

let extract_isConstructed (x : int) : bool =
  let i = (x lsr 5) land 1 in
  i = 1

let extract_shorttype (x : int) : int =
  x land 31

let extract_longtype pstate : int  =
  let rec aux accu =
    let byte = pop_byte pstate in
    let new_accu = (accu lsl 7) lor (byte land 0x7f) in
    if (byte land 0x80) = 0
    then new_accu
    else aux new_accu
  in aux 0

let extract_header pstate : (asn1_class * bool * int) =
  let hdr = pop_byte pstate in
  let c = extract_class hdr in
  let isC = extract_isConstructed hdr in
  let t = extract_shorttype hdr in
  if (t < 0x1f)
  then (c, isC, t)
  else (c, isC, extract_longtype pstate)


(* This function should use peek_byte and consider one byte has already been read *)
let extract_longtype_rewindable pstate : int * int  =
  let rec aux offset accu =
    let byte = peek_byte pstate offset in
    let new_accu = (accu lsl 7) lor (byte land 0x7f) in
    if (byte land 0x80) = 0
    then new_accu, (offset + 1)
    else aux (offset + 1) new_accu
  in aux 1 0

let extract_header_rewindable pstate : ((asn1_class * bool * int) * int) =
  let hdr = peek_byte pstate 0 in
  let c = extract_class hdr in
  let isC = extract_isConstructed hdr in
  let t = extract_shorttype hdr in
  if (t < 0x1f)
  then ((c, isC, t), 1)
  else
    let (ltype, bytesToDiscard) = extract_longtype_rewindable pstate in
    (c, isC, ltype), bytesToDiscard


let extract_length pstate name =
  let first = pop_byte pstate in
  if first land 0x80 = 0
  then go_down pstate name first
  else begin
    let accu = ref 0 in
    for i = 1 to (first land 0x7f) do
      accu := (!accu lsl 8) lor (pop_byte pstate);
    done;
    go_down pstate name !accu
  end

type parse_function = parsing_state -> asn1_content


(* Boolean *)

let raw_der_to_boolean pstate =
  let value = pop_all_bytes pstate in
  match value with
    | [] ->
      asn1_emit NotInNormalForm None (Some "empty boolean") pstate;
      false
    | [0] -> false
    | [255] -> true
    | v::_ ->
      asn1_emit NotInNormalForm None (Some "invalid value for a boolean") pstate;
      (v <> 0)

let der_to_boolean pstate = Boolean (raw_der_to_boolean pstate)


(* Integer *)

let raw_der_to_int pstate =
  let l = pop_string pstate in
  let two_first_chars =
    let n = String.length l in
    if n = 0 then []
    else if n = 1 then [int_of_char l.[0]]
    else [int_of_char l.[0] ; int_of_char l.[1]]
  in
  begin
    match two_first_chars with
      | [] -> asn1_emit NotInNormalForm None (Some "empty integer") pstate
      | x::y::_ ->
	if (x = 0xff) || ((x = 0) && (y land 0x80) = 0)
	then asn1_emit NotInNormalForm None (Some "useless prefix byte") pstate
      | _ -> ()
  end;
  l

let der_to_int pstate = Integer (raw_der_to_int pstate)


(* Null *)

let raw_der_to_null pstate =
  if not (eos pstate)
  then asn1_emit NotInNormalForm None (Some "non-empty null object") pstate

let der_to_null pstate =
  raw_der_to_null pstate;
  Null



(* OId *)

let der_to_subid pstate : int =
  let rec aux accu =
    let c = pop_byte pstate in
    let new_accu = (accu lsl 7) lor (c land 0x7f) in
    if c land 0x80 != 0
    then aux new_accu
    else new_accu
  in aux 0

let raw_der_to_oid pstate =
  let rec aux () =
    if eos pstate
    then []
    else begin
      try
	let next = der_to_subid pstate in
	next::(aux ())
      with OutOfBounds _ ->
	asn1_emit NotInNormalForm None (Some "OId contains a partial sub-id") pstate;
	[]
    end
  in
  aux ()

let der_to_oid pstate = OId (raw_der_to_oid pstate)


(* Bit String *)

let raw_der_to_bitstring _type pstate =
  let nBits =
    if eos pstate then begin
      asn1_emit NotInNormalForm None (Some "empty bit string") pstate;
      0
    end else pop_byte pstate
  in
  let content = pop_string pstate in
  (* TODO: Checks on nBits and on the final zeros *)
  (nBits, content)

let der_to_bitstring _type pstate =
  let nBits, content = raw_der_to_bitstring _type pstate in
  BitString (nBits, content)


(* Octet String *)

(* TODO: Add constraints *)
let der_to_octetstring binary pstate =
  String (pop_string pstate, binary)


(* Constructed and global function *)

let rec der_to_constructed pstate =
  let rec parse_aux () =
    if eos pstate
    then []
    else
      let next = parse pstate in
      next::(parse_aux ())
  in
  Constructed (parse_aux ())
    
and choose_parse_fun pstate (c : asn1_class) (isC : bool) (t : int) : parse_function =
  match c with
    | C_Universal when t >= 0 && t < Array.length universal_tag_map -> begin
      match (universal_tag_map.(t), isC) with
	| (T_Boolean, false) -> der_to_boolean
	| (T_Integer, false) -> der_to_int
	  
	| (T_Null, false) -> der_to_null
	  
	| (T_OId, false) -> der_to_oid
	  
	| (T_BitString, false) -> der_to_bitstring None
	  
	| (T_OctetString, false) -> der_to_octetstring true

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
	| ( T_BMPString, false) -> der_to_octetstring false
	  
	| (T_Sequence, true)
	| (T_Set, true) -> der_to_constructed
	  
	| (_, false) ->
	  asn1_emit UnknownPrimitiveUniversal None (Some (string_of_int t)) pstate;
	  der_to_octetstring true

	| (_, true) ->
	  asn1_emit UnknownConstructedUniversal None (Some (string_of_int t)) pstate;
	  der_to_constructed
    end
      
    | C_Universal ->
      asn1_emit (if isC then UnknownConstructedUniversal else UnknownPrimitiveUniversal)
	None (Some (string_of_int t)) pstate;
      if isC then der_to_constructed else der_to_octetstring true

    | _ -> if isC then der_to_constructed else der_to_octetstring true
      
and parse pstate : asn1_object =
  let offset = pstate.previous_offset + pstate.cur_offset in
  let (c, isC, t) = extract_header pstate in
  let new_pstate = extract_length pstate (string_of_header_pretty c isC t) in
  let hlen = new_pstate.previous_offset - offset in
  let len = Common.pop_option new_pstate.cur_length (-1) in
  let parse_fun = choose_parse_fun pstate c isC t in
  let res = mk_object (string_of_header_pretty c isC t)
    c t offset hlen len (parse_fun new_pstate) in
  if not (eos new_pstate) then asn1_emit UnexpectedJunk None None pstate;
  res


let exact_parse name str : asn1_object =
  let pstate = pstate_of_string name str in
  let res = parse pstate in
  if not (eos pstate)
  then failwith "Trailing bytes at the end of the string"
  else res




(**************************)
(* Content pretty printer *)
(**************************)

(* TODO: Rewrite this as options... *)
type type_representation =
  | NoType
  | RawType
  | PrettyType
  | NamedType

type data_representation =
  | NoData
  | RawData
  | PrettyData

type print_options = {
  type_repr : type_representation;
  data_repr : data_representation;
  resolver : (int list, string) Hashtbl.t option;
  indent_output : bool;     (* indent output and add eols *)
}


(* Useful func *)

let isConstructed o = match o.a_content with
  | Constructed _ -> true
  | _ -> false


let string_of_bitstring raw nBits s =
  if raw || nBits <> 0
  then "[" ^ (string_of_int nBits) ^ "]:" ^ (Common.hexdump s)
  else Common.hexdump s

let oid_expand = function
  | [] -> []
  | x::r ->
    let a, b = if x >= 80
      then 2, (x - 80)
      else (x / 40), (x mod 40)
    in a::b::r

let oid_squash = function
  | a::b::r ->
    if ((a = 0 || a = 1) && (b < 40)) || (a = 2)
    then (a * 40 + b)::r
    else raise (ContentError ("Invalid OId"))
  | _ -> raise (ContentError ("Invalid OId"))


let string_of_oid diropt oid = match diropt with
  | Some dir when Hashtbl.mem dir oid ->
    Hashtbl.find dir oid
  | _ ->
    String.concat "." (List.map string_of_int (oid_expand oid))


let rec string_of_object indent popts o =
  let type_string = match popts.type_repr with
    | NoType -> []
    | RawType -> [string_of_header_raw o.a_class (isConstructed o) o.a_tag]
    | PrettyType -> [string_of_header_pretty o.a_class (isConstructed o) o.a_tag]
    | NamedType -> [o.a_name]
  in

  let content_string = match popts.data_repr, o.a_content with
    | _, Constructed l -> [string_of_constructed indent popts l]

    | NoData, _
    | _, Null -> []

    | _, Boolean true -> ["true"]
    | _, Boolean false -> ["false"]

    | _, Integer i -> ["0x" ^ (Common.hexdump i)]

    | _, BitString (nBits, s) -> [string_of_bitstring (popts.data_repr = RawData) nBits s]
    | _, OId oid -> [string_of_oid popts.resolver oid]

    | RawData, String (s, _)
    | _, String (s, true) -> ["[HEX:]" ^ (Common.hexdump s)]  
    | _, String (s, _) -> [s]
  in

  let res = String.concat ": " (type_string@content_string) in
  if popts.indent_output
  then indent ^ res ^ "\n"
 else res

and string_of_constructed indent popts l =
  let newindent = if popts.indent_output
    then indent ^ "  "
    else indent
  in
  let objects = List.map (string_of_object newindent popts) l in
  if popts.indent_output
  then "{\n" ^ (String.concat "" objects) ^ indent ^ "}"
  else "{" ^ (String.concat "; " objects) ^ "}"




(********************)
(* Content DER dump *)
(********************)

(* Header *)

let dump_class c =
  match c with
    | C_Universal -> 0
    | C_Private -> 0x40
    | C_Application -> 0x80
    | C_ContextSpecific -> 0xc0

let dump_isConstructed isC =
  if isC then 0x20 else 0

let dump_longtype t =
  failwith "long type not implemented"

let dump_header (c : asn1_class) (isC : bool) (t : int) : string =
  let t' = if t < 0x1f then t else 0x1f in
  let h = (dump_class c) lor (dump_isConstructed isC) lor t' in
  let res = String.make 1 (char_of_int h) in
  if t' = 0x1f
  then res ^ dump_longtype t
  else res

let dump_length l =
  let rec aux accu = function
    | 0 -> accu
    | lg -> aux ((lg land 0xff)::accu) (lg lsr 8)
  in
  if l < 0x80
  then String.make 1 (char_of_int l)
  else begin
    let x = aux [] l in
    let prefix = ((List.length x) lor 0x80) in
    Common.string_of_int_list (prefix::x)
  end


(* object dump functions *)
    
let boolean_to_der b =
  if b then "\xff" else "\x00"

let subid_to_charlist id =
  let rec aux x =
    let q = x lsr 7 in
    let c = x land 0x7f in
    match q with
      | 0 -> [c]
      | _ -> c::(aux q)
  in aux id

let oid_to_der idlist =
  let cll = List.map subid_to_charlist idlist in
  Common.string_of_int_list (List.flatten cll)

let bitstring_to_der nBits s =
  let prefix = String.make 1 (char_of_int nBits) in
  prefix ^ s



let rec dump o =
  let isC, contents = match o.a_content with
    | Null -> false, ""
    | Boolean b -> false, boolean_to_der b
    | Integer i -> false, i
    | BitString (nb, s) -> false, bitstring_to_der nb s
    | OId id -> false, oid_to_der id
    | String (s, _) -> false, s
    | Constructed objects -> true, constructed_to_der objects
  in
  let hdr = dump_header o.a_class isC o.a_tag in
  let lg = dump_length (String.length contents) in
  hdr ^ lg ^ contents

and constructed_to_der objlist =
  let subdumps = List.map dump objlist in
  String.concat "" subdumps





let (name_directory : (int list, string) Hashtbl.t) = Hashtbl.create 100


module Asn1Parser = struct
  type t = asn1_object
  let name = "asn1"
  let params = []

  (* TODO: Make these options mutable from the language ? *)
  let opts = { type_repr = PrettyType; data_repr = PrettyData;
	       resolver = Some name_directory; indent_output = true };;

  let parse = parse
  let dump = dump

  let class_of_string = function
    | "Universal" -> C_Universal
    | "Application" -> C_Application
    | "Context Specific" -> C_ContextSpecific
    | "Private" -> C_Private
    | _ -> raise (ContentError ("Invalid ASN.1 class"))

  let rec value_of_asn1_content = function
    | Null -> V_Unit
    | Boolean b -> V_Bool b
    | Integer i -> V_Bigint i
    | BitString (n, s) -> V_BitString (n, s)
    | OId oid ->  V_List (List.map (fun x -> V_Int x) (oid_expand oid))
    | String (s, true) -> V_BinaryString s
    | String (s, false) -> V_String s
    | Constructed objs ->
      let value_of_constructed sub_obj =
	let d = Hashtbl.create 10 in
	enrich sub_obj d;
	V_Dict d
      in
      V_List (List.map value_of_constructed objs)

  and enrich o dict =
    Hashtbl.replace dict "name" (V_String o.a_name);
    Hashtbl.replace dict "class" (V_String (string_of_class o.a_class));
    Hashtbl.replace dict "tag" (V_Int (o.a_tag));
    Hashtbl.replace dict "tag_str" (V_String (string_of_tag o.a_class o.a_tag));
    Hashtbl.replace dict "is_constructed" (V_Bool (isConstructed o));
    begin
      match o.a_ohl with
	| None -> ()
	| Some (off, hlen, len) ->
	  Hashtbl.replace dict "offset" (V_Int off);
	  Hashtbl.replace dict "hlen" (V_Int hlen);
	  Hashtbl.replace dict "len" (V_Int len);
    end;
    Hashtbl.replace dict "content" (value_of_asn1_content o.a_content)


  let rec asn1_content_of_value = function
    | false, V_Unit -> Null
    | false, V_Bool b -> Boolean b
    | false, V_Bigint i -> Integer i
    | false, V_BitString (n, s) -> BitString (n, s)
    | false, V_BinaryString s -> String (s, true)
    | false, V_String s -> String (s, false)
    | false, V_List l ->
      OId (oid_squash (List.map eval_as_int l))
    | true, V_List l ->
      Constructed (List.map (fun x -> update (eval_as_dict x)) l)
    | _ -> raise (ContentError ("Invalid value for an asn1 content"))

  and update dict =
    let name = eval_as_string (Hashtbl.find dict "name") in
    let c = class_of_string (eval_as_string (Hashtbl.find dict "class")) in
    let t = eval_as_int (Hashtbl.find dict "tag") in
    let isC = eval_as_bool (Hashtbl.find dict "is_constructed") in
    let content = asn1_content_of_value (isC, Hashtbl.find dict "content") in
    mk_object' name c t content


  let to_string o = string_of_object "" opts o
end

module Asn1Module = MakeParserModule (Asn1Parser)
let _ = add_module ((module Asn1Module : Module))

