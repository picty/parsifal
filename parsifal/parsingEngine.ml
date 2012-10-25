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



(* Pre-defined types *)

type ipv4 = string

let parse_ipv4 = parse_string 4
let lwt_parse_ipv4 = lwt_parse_string 4

let dump_ipv4 ipv4 = ipv4

let string_of_ipv4 s =
  let elts = [s.[0]; s.[1]; s.[2]; s.[3]] in
  String.concat "." (List.map (fun e -> string_of_int (int_of_char e)) elts)

let print_ipv4 ?indent:(indent="") ?name:(name="ipv4") s =
  let res = string_of_ipv4 s in
  Printf.sprintf "%s%s: %s\n" indent name res



type ipv6 = string

let parse_ipv6 = parse_string 16
let lwt_parse_ipv6 = lwt_parse_string 16

let dump_ipv6 ipv6 = ipv6

let string_of_ipv6 s =
  let res = String.make 39 ':' in
  for i = 0 to 15 do
    let x = int_of_char (String.get s i) in
    res.[(i / 2) + i * 2] <- Common.hexa_char.[(x lsr 4) land 0xf];
    res.[(i / 2) + i * 2 + 1] <- Common.hexa_char.[x land 0xf];
  done;
  res

let print_ipv6 ?indent:(indent="") ?name:(name="ipv6") s =
  let res = string_of_ipv6 s in
  Printf.sprintf "%s%s: %s\n" indent name res
