type ctor_name = string
type choice = int * ctor_name * string

type type_name = string
type unknown_behaviour =
  | DefaultVal of string
  | UnknownVal of string
  | Exception of string
type enum = type_name * choice list * unknown_behaviour
