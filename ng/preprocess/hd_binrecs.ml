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
  | FT_Enum of integer_type * string * string
  | FT_IPv4
  | FT_IPv6
  | FT_String of field_len * bool
  | FT_List of field_len * field_type
  | FT_Container of integer_type * field_type
  | FT_Custom of string * string * string list

(* TODO: Add options for lists (AtLeast, AtMost) and for options *)

type field_desc = field_name * field_type * bool

type description = string * field_desc list
