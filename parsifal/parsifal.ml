open Lwt



(* String and Lwt input definitions *)

type string_input = {
  str : string;
  cur_name : string;
  cur_base : int;
  mutable cur_offset : int;
  cur_length : int;
  history : (string * int * int option) list
}

type lwt_input = {
  lwt_ch : Lwt_io.input_channel;
  lwt_name : string;
  mutable lwt_offset : int;
  lwt_rewindable : bool;
}

let print_string_input i =
  let rec print_history accu = function
    | [] -> String.concat ", " (List.rev accu)
    | (n, o, None)::r ->
      print_history ((Printf.sprintf "%s (%d/?)" n o)::accu) r
    | (n, o, Some l)::r ->
      print_history ((Printf.sprintf "%s (%d/%d)" n o l)::accu) r
  in
  Printf.sprintf "%s (%d/%d) [%s]" i.cur_name i.cur_offset i.cur_length (print_history [] i.history)

let print_lwt_input i =
  Printf.sprintf "%s (%d/?)" i.lwt_name i.lwt_offset

type fuzzy_input =
  | StringInput of string_input
  | LwtInput of lwt_input

let print_fuzzy_input = function
  | StringInput s -> print_string_input s
  | LwtInput l -> print_lwt_input l


type parsing_exception =
  | OutOfBounds
  | UnexpectedTrailingBytes
  | EmptyHistory
  | NonEmptyHistory
  | UnableToRewind

let print_parsing_exception = function
  | OutOfBounds -> "OutOfBounds"
  | UnexpectedTrailingBytes -> "UnexpectedTrailingBytes"
  | EmptyHistory -> "EmptyHistory"
  | NonEmptyHistory -> "NonEmptyHistory"

exception ParsingException of parsing_exception * fuzzy_input

let emit_parsing_exception fatal e i =
  if fatal
  then raise (ParsingException (e, i))
  else Printf.fprintf stderr "%s in %s\n" (print_parsing_exception e) (print_string_input i)

let emit_lwt_parsing_exception fatal e i =
  if fatal
  then raise (LwtParsingException (e,i))
  else Printf.fprintf stderr "%s in %s\n" (print_parsing_exception e) (print_lwt_input i)



(* string_input manipulation *)

let input_of_string name s = {
    str = s;
    cur_name = name;
    cur_base = 0;
    cur_offset = 0;
    cur_length = String.length s;
    history = []
  }

let get_in input name len =
  if input.cur_offset + len <= input.cur_length
  then {
    str = input.str;
    cur_name = name;
    cur_base = input.cur_base + input.cur_offset;
    cur_offset = 0;
    cur_length = len;
    history = (input.cur_name, input.cur_offset, Some input.cur_length)::input.history
  } else raise (ParsingException (OutOfBounds, StringInput input))

let get_out old_input input =
  if input.cur_offset < input.cur_length
  then raise (ParsingException (UnexpectedTrailingBytes, StringInput input))
  else old_input.cur_offset <- old_input.cur_offset + input.cur_length


let append_to_input input next_string =
  if input.cur_base = 0 && input.history = []
  then { input with
    str =  (String.sub input.str input.cur_offset (input.cur_length - input.cur_offset)) ^ next_string;
    cur_offset = 0;
    cur_length = String.length input.str
  } else { input with
    str = input.str ^ next_string;
    cur_length = input.cur_length + (String.length next_string);
  }

let drop_used_string input =
  if input.cur_base = 0 && input.history = []
  then { input with
    str = (String.sub input.str input.cur_offset (input.cur_length - input.cur_offset));
    cur_offset = 0;
    cur_length = String.length input.str
  } else raise (ParsingException (NonEmptyHistory, StringInput input))


let eos input =
  input.cur_offset >= input.cur_length

let check_empty_input fatal input =
  if not (eos input) then emit_parsing_exception fatal UnexpectedTrailingBytes input

let try_parse parse_fun input =
  if eos input then None else begin
    let saved_offset = input.cur_offset in
    try Some (parse_fun input)
    with ParsingException _ ->
      input.cur_offset <- saved_offset;
      None
  end

let exact_parse parse_fun input =
  let res = parse_fun input in
  check_empty_input true input;
  res



(* lwt_input manipulation *)

let is_rewindable ch =
  let handle_unix_error = function
    | Unix.Unix_error (Unix.ESPIPE, "lseek", "") -> return false
    | e -> fail e
  and get_length () = Lwt_io.length ch
  and is_not_null x = return (Int64.compare Int64.zero x <> 0)
  in try_bind get_length is_not_null handle_unix_error

let input_of_channel name ch =
  is_rewindable c >>= fun rewindable ->
  return { lwt_ch = ch; lwt_name = name;
	   lwt_offset = Lwt_io.position c;
	   lwt_rewindable = rewindable }

let input_of_fd name fd =
  let c = Lwt_io.of_fd Lwt_io.input fd in
  input_of_channel c

let input_of_filename filename =
  Lwt_unix.openfile filename [Unix.O_RDONLY] 0 >>= fun fd ->
  input_of_fd filename fd

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
  then fail (ParsingException (UnexpectedTrailingBytes, LwtInput input))
  else begin
    old_input.lwt_offset <- old_input.lwt_offset + input.cur_length;
    return ()
  end

(* let eos input = *)
(*   input.cur_offset >= input.cur_length *)

(* let check_empty_input fatal input = *)
(*   if not (eos input) then emit_parsing_exception fatal UnexpectedTrailingBytes input *)

let try_lwt_parse lwt_parse_fun input =
  let saved_offset = input.lwt_offset in
  let finalize_ok x = return (Some x)
  and finalie_nok = function
    | ParsingException _ ->
      input.lwt_offset <- saved_offset;
      if input.lwt_rewindable
      then begin
	Lwt_io.set_position input.lwt_ch (Int64.of_int saved_offset) >>= fun () ->
	return None
      end else fail (ParsingError (UnableToRewind, LwtInput input))
    | e -> fail e
  in try_bind (parse_fun input) finalize_ok finalize_nok

let exact_lwt_parse lwt_parse_fun input =
  fail (NotImplemented "exact_lwt_parse")
