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
  | FT_Empty
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

type record_option =
  | RO_AddParseParameter of string
  | RO_NoContextParameter

type record_description = string * field_desc list * record_option list




(* Choices (a.k.a unions) *)

type discriminator_type =
  | Explicit of string  (* the discriminator will be given as an arg *)
  | Implicit of string  (* the discriminator comes from the context *)
(* If the discriminator is Implict x
   - context is None -> Unparsed
   - context is Some context -> the discriminator is context, whatever this means (generally "context.field") *)

(* Discrimating value, Constructor name, Constructor subtype (module + type name) *)
type choice_desc = string * string * field_type

type choice_option =
  | CO_EnrichByDefault
  | CO_ExhaustiveDiscriminatingVals
  | CO_AddParseParameter of string
  | CO_NoContextParameter

(* Type name, Module containing the discriminating values, Discriminator, Choice list, Constructor if unparsed, Default value of the enrich ref *)
type choice_description = string * string option * discriminator_type * choice_desc list * string * choice_option list




type type_description =
  | Record of record_description
  | Choice of choice_description
