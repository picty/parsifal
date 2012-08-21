type string_input = {
  mutable str : string;
  cur_name : string;
  mutable cur_base : int;
  mutable cur_offset : int;
  mutable cur_length : int;
  history : (string * int * int option) list
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


type parsing_exception =
  | OutOfBounds
  | UnexpectedTrailingBytes
  | EmptyHistory
  | NonEmptyHistory

let print_parsing_exception = function
  | OutOfBounds -> "OutOfBounds"
  | UnexpectedTrailingBytes -> "UnexpectedTrailingBytes"
  | EmptyHistory -> "EmptyHistory"
  | NonEmptyHistory -> "NonEmptyHistory"

exception ParsingException of parsing_exception * string_input

let emit_parsing_exception fatal e i =
  if fatal
  then raise (ParsingException (e, i))
  else Printf.fprintf stderr "%s in %s\n" (print_parsing_exception e) (print_string_input i)


(* string_input manipulation *)

let input_of_string name s =
  {
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
  } else raise (ParsingException (OutOfBounds, input))

let get_out old_input input =
  if input.cur_offset < input.cur_length
  then raise (ParsingException (UnexpectedTrailingBytes, input))
  else old_input.cur_offset <- old_input.cur_offset + input.cur_length


let append_to_input input next_string =
  if input.cur_base = 0 && input.history = [] then begin
    input.str <- (String.sub input.str input.cur_offset (input.cur_length - input.cur_offset)) ^ next_string;
    input.cur_offset <- 0;
    input.cur_length <- String.length input.str
  end else begin
    input.str <- input.str ^ next_string;
    input.cur_length <- input.cur_length + (String.length next_string);
  end

let drop_used_string input =
  if input.cur_base = 0 && input.history = [] then begin
    input.str <- (String.sub input.str input.cur_offset (input.cur_length - input.cur_offset));
    input.cur_offset <- 0;
    input.cur_length <- String.length input.str
  end else raise (ParsingException (NonEmptyHistory, input))

let eos input =
  input.cur_offset >= input.cur_length

let check_empty_input fatal input =
  if not (eos input) then emit_parsing_exception fatal UnexpectedTrailingBytes input

let _save_input i = i.str, i.cur_base, i.cur_offset, i.cur_length
let _restore_input i (str, cb, co, cl) =
  i.str <- str;
  i.cur_base <- cb;
  i.cur_offset <- co;
  i.cur_length <- cl

let try_parse parse_fun input =
  if eos input then None else begin
    let saved_state = _save_input input in
    try Some (parse_fun input)
    with ParsingException _ ->
      _restore_input input saved_state;
      None
  end

let exact_parse parse_fun input =
  let res = parse_fun input in
  check_empty_input true input;
  res


(* Integer parsing *)

let parse_uint8 input =
  if input.cur_offset < input.cur_length then begin
    let res = int_of_char (input.str.[input.cur_base + input.cur_offset]) in
    input.cur_offset <- input.cur_offset + 1;
    res
  end else raise (ParsingException (OutOfBounds, input))

let parse_char input =
  if input.cur_offset < input.cur_length then begin
    let res = input.str.[input.cur_base + input.cur_offset] in
    input.cur_offset <- input.cur_offset + 1;
    res
  end else raise (ParsingException (OutOfBounds, input))

let parse_uint16 input =
  if input.cur_offset + 2 <= input.cur_length then begin
    let res =
      (int_of_char (input.str.[input.cur_base + input.cur_offset]) lsl 8) lor
	(int_of_char (input.str.[input.cur_base + input.cur_offset + 1]))
    in
    input.cur_offset <- input.cur_offset + 2;
    res
  end else raise (ParsingException (OutOfBounds, input))

let peek_uint16 input =
  if input.cur_offset + 2 <= input.cur_length then begin
    (int_of_char (input.str.[input.cur_base + input.cur_offset]) lsl 8) lor
      (int_of_char (input.str.[input.cur_base + input.cur_offset + 1]))
  end else raise (ParsingException (OutOfBounds, input))

let parse_uint24 input =
  if input.cur_offset + 3 <= input.cur_length then begin
    let res =
      (int_of_char (input.str.[input.cur_base + input.cur_offset]) lsl 16) lor
      (int_of_char (input.str.[input.cur_base + input.cur_offset + 1]) lsl 8) lor
	(int_of_char (input.str.[input.cur_base + input.cur_offset + 2]))
    in
    input.cur_offset <- input.cur_offset + 3;
    res
  end else raise (ParsingException (OutOfBounds, input))

let parse_uint32 input =
  if input.cur_offset + 2 <= input.cur_length then begin
    let res =
      (int_of_char (input.str.[input.cur_base + input.cur_offset]) lsl 24) lor
      (int_of_char (input.str.[input.cur_base + input.cur_offset + 1]) lsl 16) lor
      (int_of_char (input.str.[input.cur_base + input.cur_offset + 2]) lsl 8) lor
	(int_of_char (input.str.[input.cur_base + input.cur_offset + 3]))
    in
    input.cur_offset <- input.cur_offset + 4;
    res
  end else raise (ParsingException (OutOfBounds, input))



(* String parsing *)

let parse_string n input =
  if input.cur_offset + n <= input.cur_length then begin
    let res = String.sub input.str (input.cur_base + input.cur_offset) n in
    input.cur_offset <- input.cur_offset + n;
    res
  end else raise (ParsingException (OutOfBounds, input))

let parse_rem_string input =
  let res = String.sub input.str (input.cur_base + input.cur_offset) (input.cur_length - input.cur_offset) in
  input.cur_offset <- input.cur_length;
  res

let parse_varlen_string name len_fun input =
  let n = len_fun input in
  let new_input = get_in input name n in
  let res = parse_rem_string new_input in
  get_out input new_input;
  res

let drop_bytes n input =
  if input.cur_offset + n <= input.cur_length
  then input.cur_offset <- input.cur_offset + n
  else raise (ParsingException (OutOfBounds, input))

let drop_rem_bytes input =
  input.cur_offset <- input.cur_length



(* List parsing *)

let parse_list n parse_fun input =
  let rec aux accu = function
    | 0 -> List.rev accu
    | i ->
      let x = parse_fun input in
      aux (x::accu) (i-1)
  in aux [] n

let parse_rem_list parse_fun input =
  let rec aux accu =
    if eos input
    then List.rev accu
    else begin
      let x = parse_fun input in
      aux (x::accu)
    end
  in aux []

let parse_varlen_list name len_fun parse_fun input =
  let n = len_fun input in
  let new_input = get_in input name n in
  let res = parse_rem_list parse_fun new_input in
  get_out input new_input;
  res

let parse_container name n parse_fun input =
  let new_input = get_in input name n in
  let res = parse_fun new_input in
  get_out input new_input;
  res

let parse_varlen_container name len_fun parse_fun input =
  let n = len_fun input in
  parse_container name n parse_fun input
