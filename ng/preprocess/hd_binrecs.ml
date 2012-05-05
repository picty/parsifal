type field_name = string

type integer_type =
  | IT_UInt8
  | IT_UInt16
  | IT_UInt24
  | IT_UInt32

type field_len =
  | FixedLen of int
  | VarLen of integer_type
  | Remaining

type field_type =
  | FT_Char
  | FT_Integer of integer_type
  | FT_IPv4
  | FT_IPv6
  | FT_String of field_len
  | FT_List of field_len * field_type
  | FT_Custom of string

(* TODO: Add options for lists (AtLeast, AtMost) and for options *)

type field_desc = field_name * field_type

type description = string * field_desc list
