(* BINARY RECORDS *)


(* Simple records (a.k.a structs) *)

type integer_type =
  | IT_UInt8
  | IT_UInt16
  | IT_UInt24
  | IT_UInt32

type field_name = string

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
  | FT_Custom of (string option) * string * (string list)

(* TODO: Add options for lists (AtLeast, AtMost) and for options *)

type field_desc = field_name * field_type * bool

type record_description = string * field_desc list




(* Choices (a.k.a unions) *)

(* Discrimating value, Constructor name, Constructor subtype (module + type name) *)
type choice_desc = string * string * string option * string

(* Type name, Module of the discriminating value, Choice list, Constructor if unparsed *)
type choice_description = string * string option * choice_desc list * string




type type_description =
  | Record of record_description
  | Choice of choice_description
