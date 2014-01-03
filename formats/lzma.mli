external lzma_getsize: string -> int -> int = "caml_lzma_getsize"

(* lzma_decode src src_size dst dst_size -> 0 if success
 * dst must be of size dst_size, and must be big enough
 *)
external lzma_decode: string -> int -> string -> int -> int = "caml_lzma_decode"

type 'a lzma_container = 'a
val parse_lzma_container :
  string -> (Parsifal.string_input -> 'a) -> Parsifal.string_input -> 'a
val dump_lzma_container : 'a -> 'b -> 'c -> 'd
val value_of_lzma_container : ('a -> 'b) -> 'a -> 'b

