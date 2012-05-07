type field_name = string

type field_type =
  | AT_Boolean
  | AT_SmallInteger
  | AT_Integer
(*  | AT_BitString *)
(*  | AT_EnumeratedBitString *)
  | AT_Null
  | AT_OId
(*  | AT_String *)
  | AT_Primitive
  | AT_Custom of string * string

type expected_header_string = string option

(* Add a way to have an optional field
   Add a way to enrich with
      * offset / hlen / len
      * class / tag info
      * hash of the asn1 object
      * string of the asn1 object *)

type field_desc = field_name * field_type * expected_header_string

type description = string * field_desc list * expected_header_string

