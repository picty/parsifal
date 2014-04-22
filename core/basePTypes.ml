open Parsifal


(************)
(* Integers *)
(************)

type uint8 = int

let parse_uint8 = parse_byte

let peek_uint8 input =
  if input.cur_offset < input.cur_length then begin
    int_of_char (input.str.[input.cur_base + input.cur_offset])
  end else raise (ParsingException (OutOfBounds, _h_of_si input))

let dump_uint8 buf v = POutput.add_byte buf (v land 0xff)

let value_of_uint8 i = VInt (i, 8, LittleEndian)



type uint16 = int

let parse_uint16 input =
  if input.cur_offset + 2 <= input.cur_length then begin
    let res =
      (int_of_char (input.str.[input.cur_base + input.cur_offset]) lsl 8) lor
	(int_of_char (input.str.[input.cur_base + input.cur_offset + 1]))
    in
    input.cur_offset <- input.cur_offset + 2;
    res
  end else raise (ParsingException (OutOfBounds, _h_of_si input))

let peek_uint16 input =
  if input.cur_offset + 2 <= input.cur_length then begin
    (int_of_char (input.str.[input.cur_base + input.cur_offset]) lsl 8) lor
      (int_of_char (input.str.[input.cur_base + input.cur_offset + 1]))
  end else raise (ParsingException (OutOfBounds, _h_of_si input))

let dump_uint16 buf v =
  POutput.add_byte buf ((v lsr 8) land 0xff);
  POutput.add_byte buf (v land 0xff)

let value_of_uint16 i = VInt (i, 16, BigEndian)



type uint16le = int

let parse_uint16le input =
  if input.cur_offset + 2 <= input.cur_length then begin
    let res =
      (int_of_char (input.str.[input.cur_base + input.cur_offset + 1]) lsl 8) lor
	(int_of_char (input.str.[input.cur_base + input.cur_offset]))
    in
    input.cur_offset <- input.cur_offset + 2;
    res
  end else raise (ParsingException (OutOfBounds, _h_of_si input))

let dump_uint16le buf v =
  POutput.add_byte buf (v land 0xff);
  POutput.add_byte buf ((v lsr 8) land 0xff)

let value_of_uint16le i = VInt (i, 16, LittleEndian)



type uint24 = int

let parse_uint24 input =
  if input.cur_offset + 3 <= input.cur_length then begin
    let res =
      (int_of_char (input.str.[input.cur_base + input.cur_offset]) lsl 16) lor
      (int_of_char (input.str.[input.cur_base + input.cur_offset + 1]) lsl 8) lor
	(int_of_char (input.str.[input.cur_base + input.cur_offset + 2]))
    in
    input.cur_offset <- input.cur_offset + 3;
    res
  end else raise (ParsingException (OutOfBounds, _h_of_si input))

let dump_uint24 buf v =
  POutput.add_byte buf ((v lsr 16) land 0xff);
  POutput.add_byte buf ((v lsr 8) land 0xff);
  POutput.add_byte buf (v land 0xff)

let value_of_uint24 i = VInt (i, 24, BigEndian)


type uint24le = int

let parse_uint24le input =
  if input.cur_offset + 3 <= input.cur_length then begin
    let res =
      (int_of_char (input.str.[input.cur_base + input.cur_offset + 2]) lsl 16) lor
      (int_of_char (input.str.[input.cur_base + input.cur_offset + 1]) lsl 8) lor
      (int_of_char (input.str.[input.cur_base + input.cur_offset]))
    in
    input.cur_offset <- input.cur_offset + 3;
    res
  end else raise (ParsingException (OutOfBounds, _h_of_si input))

let dump_uint24le buf v =
  POutput.add_byte buf ((v lsr 16) land 0xff);
  POutput.add_byte buf ((v lsr 8) land 0xff);
  POutput.add_byte buf (v land 0xff)

let value_of_uint24le i = VInt (i, 24, BigEndian)



type uint32 = int (* TODO? *)

let parse_uint32 input =
  if input.cur_offset + 4 <= input.cur_length then begin
    let res =
      (int_of_char (input.str.[input.cur_base + input.cur_offset]) lsl 24) lor
      (int_of_char (input.str.[input.cur_base + input.cur_offset + 1]) lsl 16) lor
      (int_of_char (input.str.[input.cur_base + input.cur_offset + 2]) lsl 8) lor
	(int_of_char (input.str.[input.cur_base + input.cur_offset + 3]))
    in
    input.cur_offset <- input.cur_offset + 4;
    res
  end else raise (ParsingException (OutOfBounds, _h_of_si input))

let dump_uint32 buf v =
  POutput.add_byte buf ((v lsr 24) land 0xff);
  POutput.add_byte buf ((v lsr 16) land 0xff);
  POutput.add_byte buf ((v lsr 8) land 0xff);
  POutput.add_byte buf (v land 0xff)

let value_of_uint32 i = VInt (i, 32, BigEndian)



type uint32le = int (* TODO? *)

let parse_uint32le input =
  if input.cur_offset + 4 <= input.cur_length then begin
    let res =
      (int_of_char (input.str.[input.cur_base + input.cur_offset + 3]) lsl 24) lor
      (int_of_char (input.str.[input.cur_base + input.cur_offset + 2]) lsl 16) lor
      (int_of_char (input.str.[input.cur_base + input.cur_offset + 1]) lsl 8) lor
	(int_of_char (input.str.[input.cur_base + input.cur_offset]))
    in
    input.cur_offset <- input.cur_offset + 4;
    res
  end else raise (ParsingException (OutOfBounds, _h_of_si input))

let dump_uint32le buf v =
  POutput.add_byte buf (v land 0xff);
  POutput.add_byte buf ((v lsr 8) land 0xff);
  POutput.add_byte buf ((v lsr 16) land 0xff);
  POutput.add_byte buf ((v lsr 24) land 0xff)

let value_of_uint32le i = VInt (i, 32, LittleEndian)


(* TODO: Should this be rewritten with a little more elegance? *)
type uint64 = Int64.t

let parse_uint64 input =
  if input.cur_offset + 8 <= input.cur_length then begin
    let res1 =
      (int_of_char (input.str.[input.cur_base + input.cur_offset + 4]) lsl 24) lor
      (int_of_char (input.str.[input.cur_base + input.cur_offset + 5]) lsl 16) lor
      (int_of_char (input.str.[input.cur_base + input.cur_offset + 6]) lsl 8) lor
      (int_of_char (input.str.[input.cur_base + input.cur_offset + 7]))
    in
    let res2 =
      (int_of_char (input.str.[input.cur_base + input.cur_offset]) lsl 24) lor
      (int_of_char (input.str.[input.cur_base + input.cur_offset + 1]) lsl 16) lor
      (int_of_char (input.str.[input.cur_base + input.cur_offset + 2]) lsl 8) lor
      (int_of_char (input.str.[input.cur_base + input.cur_offset + 3]))
    in
    input.cur_offset <- input.cur_offset + 8;
    Int64.logor (Int64.shift_left (Int64.of_int res2) 32) (Int64.of_int res1)
  end else raise (ParsingException (OutOfBounds, _h_of_si input))

let dump_uint64 buf v =
  let ff = Int64.of_int 0xff in
  let aux offset =
    Int64.to_int (Int64.logand (Int64.shift_right v offset) ff)
  in
  POutput.add_byte buf (aux 56); POutput.add_byte buf (aux 48);
  POutput.add_byte buf (aux 40); POutput.add_byte buf (aux 32);
  POutput.add_byte buf (aux 24); POutput.add_byte buf (aux 16);
  POutput.add_byte buf (aux 8); POutput.add_byte buf (aux 0)

let value_of_uint64 i = VBigInt (exact_dump dump_uint64 i, BigEndian)



type uint64le = Int64.t

let parse_uint64le input =
  if input.cur_offset + 8 <= input.cur_length then begin
    let res1 =
      (int_of_char (input.str.[input.cur_base + input.cur_offset + 3]) lsl 24) lor
      (int_of_char (input.str.[input.cur_base + input.cur_offset + 2]) lsl 16) lor
      (int_of_char (input.str.[input.cur_base + input.cur_offset + 1]) lsl 8) lor
      (int_of_char (input.str.[input.cur_base + input.cur_offset]))
    in
    let res2 =
      (int_of_char (input.str.[input.cur_base + input.cur_offset + 7]) lsl 24) lor
      (int_of_char (input.str.[input.cur_base + input.cur_offset + 6]) lsl 16) lor
      (int_of_char (input.str.[input.cur_base + input.cur_offset + 5]) lsl 8) lor
      (int_of_char (input.str.[input.cur_base + input.cur_offset + 4]))
    in
    input.cur_offset <- input.cur_offset + 8;
    Int64.logor (Int64.shift_left (Int64.of_int res2) 32) (Int64.of_int res1)
  end else raise (ParsingException (OutOfBounds, _h_of_si input))

let dump_uint64le buf v =
  let ff = Int64.of_int 0xff in
  let aux offset =
    Int64.to_int (Int64.logand (Int64.shift_right v offset) ff)
  in
  POutput.add_byte buf (aux 0); POutput.add_byte buf (aux 8);
  POutput.add_byte buf (aux 16); POutput.add_byte buf (aux 24);
  POutput.add_byte buf (aux 32); POutput.add_byte buf (aux 40);
  POutput.add_byte buf (aux 48); POutput.add_byte buf (aux 56)

let value_of_uint64le i = VBigInt (exact_dump dump_uint64 i, LittleEndian)



type sint8 = int
let parse_sint8 input =
  let v = parse_byte input in
  if v >= 128 then (v - 256) else v
let dump_sint8 buf sint =
  let v = if sint < 0 then 256 + sint else sint in
  dump_uint8 buf v
let value_of_sint8 v = VInt (v, 8, BigEndian)

type sint16 = int
let parse_sint16 input =
  let v = parse_uint16 input in
  if v >= 32768 then (v - 65536) else v
let dump_sint16 buf sint =
  let v = if sint < 0 then 65536 + sint else sint in
  dump_uint16 buf v
let value_of_sint16 v = VInt (v, 16, BigEndian)

type sint32 = int
let parse_sint32 input =
  let v = parse_uint32 input in
  if v >= 0x8000_0000 then (v - 0x1_0000_0000) else v
let dump_sint32 buf sint =
  let v = if sint < 0 then 0x1_0000_0000 + sint else sint in
  dump_uint32 buf v
let value_of_sint32 v = VInt (v, 32, BigEndian)



(***********)
(* Strings *)
(***********)

type s = string
type string = s
let parse_string n input =
  if input.cur_offset + n <= input.cur_length then begin
    let res = String.sub input.str (input.cur_base + input.cur_offset) n in
    input.cur_offset <- input.cur_offset + n;
    res
  end else raise (ParsingException (OutOfBounds, _h_of_si input))
let dump_string buf s = POutput.add_string buf s
let value_of_string s = VString (s, false)

let peek_string n input =
  if input.cur_offset + n <= input.cur_length
  then String.sub input.str (input.cur_base + input.cur_offset) n
  else raise (ParsingException (OutOfBounds, _h_of_si input))


type binstring = string
let parse_binstring = parse_string
let dump_binstring = dump_string
let value_of_binstring s = VString (s, true)


type rem_string = string
let parse_rem_string input =
  let res = String.sub input.str (input.cur_base + input.cur_offset) (input.cur_length - input.cur_offset) in
  input.cur_offset <- input.cur_length;
  res
let dump_rem_string = dump_string
let value_of_rem_string = value_of_string


type rem_binstring = string
let parse_rem_binstring = parse_rem_string
let dump_rem_binstring = dump_string
let value_of_rem_binstring = value_of_binstring


type varlen_string = string
let parse_varlen_string len_fun input =
  let n = len_fun input in
  parse_string n input
let dump_varlen_string len_fun buf s =
  let n = String.length s in
  len_fun buf n;
  POutput.add_string buf s
let value_of_varlen_string = value_of_string


type varlen_binstring = string
let parse_varlen_binstring = parse_varlen_string
let dump_varlen_binstring = dump_varlen_string
let value_of_varlen_binstring = value_of_binstring


type string_until = string
let parse_string_until c input =
  if input.cur_offset < input.cur_length then begin
    let offset = input.cur_base + input.cur_offset in
    try
      let index = String.index_from input.str offset c in
      let res = parse_string (index - offset) input in
      ignore (parse_byte input);
      res
    with Not_found -> parse_rem_string input
  end else raise (ParsingException (OutOfBounds, _h_of_si input))
let dump_string_until c buf s =
  POutput.add_string buf s;
  POutput.add_char buf c
let value_of_string_until = value_of_string



(********************)
(* Drop bytes utils *)
(********************)

let drop_bytes n input =
  if input.cur_offset + n <= input.cur_length
  then input.cur_offset <- input.cur_offset + n
  else raise (ParsingException (OutOfBounds, _h_of_si input))

let drop_rem_bytes input =
  input.cur_offset <- input.cur_length



(**********************)
(* List and container *)
(**********************)

let parse_list n _name parse_fun input =
  let rec aux accu = function
    | 0 -> List.rev accu
    | i ->
      let x = parse_fun input in
      aux (x::accu) (i-1)
  in aux [] n

let dump_list dump_fun buf l = List.iter (dump_fun buf) l

let value_of_list sub_fun l = VList (List.map sub_fun l)


type 'a rem_list = 'a list

let parse_rem_list _name parse_fun input =
  let rec aux accu =
    if eos input
    then List.rev accu
    else begin
      let saved_offset = input.cur_offset in
      let next_elt =
	try Some (parse_fun input)
	with ParsingStop -> None
      in
      match next_elt with
      | None ->
	input.cur_offset <- saved_offset;
	List.rev accu
      | Some x -> aux (x::accu)
    end
  in aux []

let dump_rem_list = dump_list

let value_of_rem_list = value_of_list


type 'a varlen_list = 'a list

let parse_varlen_list len_fun name parse_fun input =
  let n = len_fun input in
  let new_input = get_in input name n in
  let res = parse_rem_list name parse_fun new_input in
  get_out input new_input;
  res

let dump_varlen_list len_fun dump_fun buf l =
  let tmp_buf = POutput.create () in
  dump_list dump_fun tmp_buf l;
  let n = POutput.length tmp_buf in
  len_fun buf n;
  POutput.add_output buf tmp_buf

let value_of_varlen_list = value_of_list



(*************)
(* Container *)
(*************)

type 'a container = 'a

let parse_container n name parse_fun input =
  let new_input = get_in input name n in
  let res = parse_fun new_input in
  get_out input new_input;
  res

let dump_container dump_fun buf content = dump_fun buf content

let value_of_container value_of_fun x = value_of_fun x


type 'a varlen_container = 'a

let parse_varlen_container len_fun name parse_fun input =
  let n = len_fun input in
  parse_container n name parse_fun input

let dump_varlen_container len_fun dump_fun buf content =
  let tmp_buf = POutput.create () in
  dump_fun tmp_buf content;
  let n = POutput.length tmp_buf in
  len_fun buf n;
  POutput.add_output buf tmp_buf

let value_of_varlen_container = value_of_container


(*********)
(* Array *)
(*********)

let parse_array n _name parse_fun input =
  Array.init n (fun _ -> parse_fun input)

let dump_array dump_fun buf a =
  Array.iter (dump_fun buf) a

let value_of_array sub_fun a = VList (List.map sub_fun (Array.to_list a))



(**************)
(* Bit fields *)
(**************)

type bit_bool = bool
let parse_bit_bool input = (parse_bits 1 input) = 1
let dump_bit_bool buf b = POutput.add_bits buf 1 (if b then 1 else 0)
let value_of_bit_bool b = VBool b

type bit_int = int
let parse_bit_int nbits input = parse_bits nbits input
let dump_bit_int nbits buf i = POutput.add_bits buf nbits i
let value_of_bit_int i = VSimpleInt i

type rtol_bit_bool = bool
let parse_rtol_bit_bool input = (parse_rtol_bits 1 input) = 1
let dump_rtol_bit_bool _buf _b = raise (ParsingException (NotImplemented "dump_rtol_bit_bool", []))
let value_of_rtol_bit_bool b = VBool b

type rtol_bit_int = int
let parse_rtol_bit_int nbits input = parse_rtol_bits nbits input
let dump_rtol_bit_int _nbits _buf _i = raise (ParsingException (NotImplemented "dump_rtol_bit_int", []))
let value_of_rtol_bit_int i = VSimpleInt i
