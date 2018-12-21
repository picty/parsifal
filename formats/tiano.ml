open Parsifal
open BasePTypes

external tiano_getsize: string -> int -> int = "caml_tiano_getsize"

external tiano_decode: string -> int -> bytes -> int -> int = "caml_tiano_decode"

type 'a tiano_container = 'a

let parse_tiano_container name parse_fun input =
  let buf = parse_rem_string input in
  let length = String.length buf in
  let dst_size = tiano_getsize buf length in
  let dst = Bytes.create dst_size in
  let ret = tiano_decode buf length dst dst_size in
  if ret <> 0 then raise (Failure "Tiano decompression error");
  let new_input = get_in_container input name (Bytes.to_string dst) in  (* TODO: Use unsafe_to_string? *)
  let res = parse_fun new_input in
  check_empty_input true new_input;
  res

let dump_tiano_container _ _buf _ = failwith "dump_tiano_container not implemented"

let value_of_tiano_container = value_of_container
