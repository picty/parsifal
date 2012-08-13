open Lwt
open ParsingEngine

type lwt_input = {
  lwt_ch : Lwt_io.input_channel;
  lwt_name : string;
  mutable lwt_offset : int;
}

let print_lwt_input i =
  Printf.sprintf "%s (%d/?)" i.lwt_name i.lwt_offset


type lwt_parsing_exception =
  | LwtOutOfBounds

let print_parsing_exception = function
  | LwtOutOfBounds -> "OutOfBounds"

exception LwtParsingException of lwt_parsing_exception * lwt_input

let emit_lwt_parsing_exception fatal e i =
  if fatal
  then raise (LwtParsingException (e,i))
  else Printf.fprintf stderr "%s in %s\n" (print_parsing_exception e) (print_lwt_input i)


let input_of_fd name fd =
  {
    lwt_ch = Lwt_io.of_fd Lwt_io.input fd;
    lwt_name = name;
    lwt_offset = 0;
  }

let input_of_channel name ch =
  {
    lwt_ch = ch;
    lwt_name = name;
    lwt_offset = 0;
  }

let really_read ch len =
  let buf = String.make len ' ' in
  Lwt_io.read_into_exactly ch buf 0 len >>= fun () ->
  return buf

let get_in input name len =
  really_read input.lwt_ch len >>= fun s ->
  return {
    str = s;
    cur_name = name;
    cur_base = 0;
    cur_offset = 0;
    cur_length = len;
    history = [input.lwt_name, input.lwt_offset, None]
  }

let get_out old_input input =
  if input.cur_offset < input.cur_length
  then fail (ParsingException (UnexpectedTrailingBytes, input))
  else begin
    old_input.lwt_offset <- old_input.lwt_offset + input.cur_length;
    return ()
  end

let try_lwt_parse lwt_parse_fun input =
  fail (Common.NotImplemented "try_lwt_parse")


(* Integer parsing *)

let lwt_parse_uint8 input =
  really_read input.lwt_ch 1 >>= fun s ->
  let res = int_of_char (s.[0]) in
  input.lwt_offset <- input.lwt_offset + 1;
  return res

let lwt_parse_char input =
  really_read input.lwt_ch 1 >>= fun s ->
  let res = s.[0] in
  input.lwt_offset <- input.lwt_offset + 1;
  return res

let lwt_parse_uint16 input =
  really_read input.lwt_ch 2 >>= fun s ->
  let res = ((int_of_char s.[0]) lsl 8) lor (int_of_char s.[1]) in
  input.lwt_offset <- input.lwt_offset + 2;
  return res

let lwt_parse_uint24 input =
  really_read input.lwt_ch 3 >>= fun s ->
  let res = ((int_of_char s.[0]) lsl 16) lor
    ((int_of_char s.[1]) lsl 8) lor (int_of_char s.[2]) in
  input.lwt_offset <- input.lwt_offset + 3;
  return res

let lwt_parse_uint32 input =
  really_read input.lwt_ch 4 >>= fun s ->
  let res = ((int_of_char s.[0]) lsl 24) lor ((int_of_char s.[1]) lsl 16)
    lor ((int_of_char s.[2]) lsl 8) lor (int_of_char s.[3]) in
  input.lwt_offset <- input.lwt_offset + 4;
  return res



(* String parsing *)

let lwt_parse_string n input =
  really_read input.lwt_ch n >>= fun s ->
  input.lwt_offset <- input.lwt_offset + n;
  return s

let lwt_parse_rem_string name input =
  fail (Common.NotImplemented "lwt_parse_rem_string")

let lwt_parse_varlen_string name len_fun input =
  len_fun input >>= fun n ->
  get_in input name n >>= fun str_input ->
  let res = parse_rem_string str_input in
  get_out input str_input >>= fun () ->
  return res

let lwt_drop_bytes n input =
  really_read input.lwt_ch n >>= fun _ ->
  input.lwt_offset <- input.lwt_offset + n;
  return ()



(* List parsing *)

let lwt_parse_list n parse_fun input =
  let rec aux accu = function
    | 0 -> return (List.rev accu)
    | i ->
      parse_fun input >>= fun x ->
      aux (x::accu) (i-1)
  in aux [] n

let lwt_parse_rem_list name input =
  fail (Common.NotImplemented "lwt_parse_rem_list")

let lwt_parse_varlen_list name len_fun parse_fun input =
  len_fun input >>= fun n ->
  get_in input name n >>= fun str_input ->
  wrap2 parse_rem_list parse_fun str_input >>= fun res ->
  get_out input str_input >>= fun () ->
  return res

let lwt_parse_container name len_fun parse_fun input =
  len_fun input >>= fun n ->
  get_in input name n >>= fun str_input ->
  wrap1 parse_fun str_input >>= fun res ->
  get_out input str_input >>= fun () ->
  return res
