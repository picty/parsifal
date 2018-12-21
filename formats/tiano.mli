external tiano_getsize: string -> int -> int = "caml_tiano_getsize"

(* tiano_decode src src_size dst dst_size -> 0 if success
 * dst must be of size dst_size, and must be big enough
 *)
external tiano_decode: string -> int -> bytes -> int -> int = "caml_tiano_decode"

type 'a tiano_container = 'a
val parse_tiano_container :
  string -> (Parsifal.string_input -> 'a) -> Parsifal.string_input -> 'a
val dump_tiano_container : 'a -> 'b -> 'c -> 'd
val value_of_tiano_container : ('a -> 'b) -> 'a -> 'b

