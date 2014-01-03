open Parsifal
open BasePTypes

external lzma_getsize: string -> int -> int = "caml_lzma_getsize"

external lzma_decode: string -> int -> string -> int -> int = "caml_lzma_decode"

type 'a lzma_container = 'a

let parse_lzma_container name parse_fun input =
  let buf = parse_rem_string input in
  let length = String.length buf in
  let dst_size = lzma_getsize buf length in
  let dst = String.create dst_size in
  let ret = lzma_decode buf length dst dst_size in
  if ret <> 0 then raise (Failure "LZMA decompression error");
  let new_input = get_in_container input name dst in
  let res = parse_fun new_input in
  check_empty_input true new_input;
  res

let dump_lzma_container _ buf _ = failwith "dump_lzma_container not implemented"

let value_of_lzma_container = value_of_container
