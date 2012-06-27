type field_name = string

type expected_header_string = string option

type field_type =
  | AT_Boolean
  | AT_SmallInteger
  | AT_Integer
  | AT_BitString
(*  | AT_EnumeratedBitString *)
  | AT_Null
  | AT_OId
  (* AT_String (constraints : None -> no_constraint, Some s -> $s_constraint) *)
  | AT_String of string option
  | AT_Primitive
  | AT_Container of expected_header_string * field_type
  (* AT_SequenceOf (name of the sequence [default is proposed_name_list], min, max, sub_type, sub_header) *)
  | AT_SequenceOf of string option * int option * int option * expected_header_string * field_type
  | AT_SetOf of string option * int option * int option * expected_header_string * field_type

  | AT_Custom of string option * string
  | AT_Anything

(* TODO: Add constraints
    - optional fields SHOULDs and SHOULDNOTs
*)

(* TODO: Add a way to enrich with
      * offset / hlen / len
      * class / tag info
      * hash of the asn1 object
      * string of the asn1 object *)

(* Name, type, optional?, Header expected (if we need to override the default) *)
type field_desc = field_name * field_type * bool * expected_header_string

type description = string * field_desc list * expected_header_string

