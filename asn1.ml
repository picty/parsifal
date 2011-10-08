(* Types *)

type asn1_class =
  | C_Universal
  | C_Application
  | C_ContextSpecific
  | C_Private

let class_map = [| C_Universal; C_Application;
		   C_ContextSpecific; C_Private |]

let string_of_class = function
  | C_Universal -> "Universal"
  | C_Application -> "Application"
  | C_ContextSpecific -> "Context Specific"
  | C_Private -> "Private"


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


type asn1_object = {
  a_class : asn1_class;
  a_tag : int;
  a_content : asn1_content;
  a_name : string;
}

and asn1_content =
  | EndOfContents
  | Boolean of bool
  | Integer of Big_int.big_int
  | BitString of int * string
  | Null
  | OId of int list
  | String of (string * bool)       (* bool : isBinary *)
  | Constructed of asn1_object list
  | Unknown of string

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

let hexa_char = [| '0'; '1'; '2'; '3';
		   '4'; '5'; '6'; '7';
		   '8'; '9'; 'a'; 'b';
		   'c'; 'd'; 'e'; 'f' |]

let only_ascii s =
  let len = String.length s in
  let res = String.make len ' ' in
  for i = 0 to (len - 1) do
    let c = String.get s i in
    let x = int_of_char c in
    if x >= 32 && x < 128
    then res.[i] <- c
  done;
  res

let hexdump s =
  let len = String.length s in
  let res = String.make (len * 2) ' ' in
  for i = 0 to (len - 1) do
    let x = int_of_char (String.get s i) in
    res.[i * 2] <- hexa_char.((x lsr 4) land 0xf);
    res.[i * 2 + 1] <- hexa_char.(x land 0xf);
  done;
  res

let isConstructed o = match o.a_content with
  | Constructed _ -> true
  | _ -> false


let string_of_bitstring raw nBits s =
  if raw && nBits == 0
  then "[" ^ (string_of_int nBits) ^ "]:" ^ (hexdump s)
  else hexdump s

let string_of_oid diropt oid = match diropt with
  | Some dir when Hashtbl.mem dir oid ->
    Hashtbl.find dir oid
  | _ ->
    String.concat "." (List.map string_of_int oid)


let rec string_of_object indent popts o =

  let type_string = match popts.type_repr with
    | NoType -> []
    | RawType -> [string_of_header_raw o.a_class (isConstructed o) o.a_tag]
    | PrettyType -> [string_of_header_pretty o.a_class (isConstructed o) o.a_tag]
    | NamedType -> [o.a_name]
  in

  let content_string = match popts.data_repr, o.a_content with
    | NoData, _
    | _, EndOfContents
    | _, Null -> []

    | _, Boolean true -> ["true"]
    | _, Boolean false -> ["false"]

    (* TODO: I would like it to be in hexa *)
    | _, Integer i -> [Big_int.string_of_big_int i]

    | _, BitString (nBits, s) -> [string_of_bitstring (popts.data_repr = RawData) nBits s]
    | _, OId oid -> [string_of_oid popts.resolver oid]

    | RawData, String (s, _)
    | _, String (s, true)
    | _, Unknown s -> ["[HEX:]" ^ (hexdump s)]  
    | _, String (s, _) -> [s]

    | _, Constructed l -> [string_of_constructed indent popts l]
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
