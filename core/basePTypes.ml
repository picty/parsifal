open Lwt
open Parsifal


(************)
(* Integers *)
(************)

let parse_uint8 = parse_byte

let peek_uint8 input =
  if input.cur_offset < input.cur_length then begin
    int_of_char (input.str.[input.cur_base + input.cur_offset])
  end else raise (ParsingException (OutOfBounds, _h_of_si input))

let lwt_parse_uint8 = lwt_parse_byte

let dump_uint8 v = String.make 1 (char_of_int (v land 0xff))

let value_of_uint8 i = VInt (i, 8, LittleEndian)



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

let lwt_parse_uint16 input =
  lwt_really_read input 2 >>= fun s ->
  return (((int_of_char s.[0]) lsl 8) lor (int_of_char s.[1]))

let dump_uint16 v =
  let c0 = char_of_int ((v lsr 8) land 0xff)
  and c1 = char_of_int (v land 0xff) in
  let res = String.make 2 c0 in
  res.[1] <- c1;
  res

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

let lwt_parse_uint16le input =
  lwt_really_read input 2 >>= fun s ->
  return (((int_of_char s.[1]) lsl 8) lor (int_of_char s.[0]))

let dump_uint16le v =
  let c1 = char_of_int ((v lsr 8) land 0xff)
  and c0 = char_of_int (v land 0xff) in
  let res = String.make 2 c0 in
  res.[1] <- c1;
  res

let value_of_uint16le i = VInt (i, 16, LittleEndian)



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

let lwt_parse_uint24 input =
  lwt_really_read input 3 >>= fun s ->
  return (((int_of_char s.[0]) lsl 16) lor
    ((int_of_char s.[1]) lsl 8) lor (int_of_char s.[2]))

let dump_uint24 v =
  let c0 = char_of_int ((v lsr 16) land 0xff)
  and c1 = char_of_int ((v lsr 8) land 0xff)
  and c2 = char_of_int (v land 0xff) in
  let res = String.make 3 c0 in
  res.[1] <- c1;
  res.[2] <- c2;
  res

let value_of_uint24 i = VInt (i, 24, BigEndian)



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
  end else raise (ParsingException (OutOfBounds, _h_of_si input))

let lwt_parse_uint32 input =
  lwt_really_read input 4 >>= fun s ->
  return (((int_of_char s.[0]) lsl 24) lor ((int_of_char s.[1]) lsl 16)
    lor ((int_of_char s.[2]) lsl 8) lor (int_of_char s.[3]))

let dump_uint32 v =
  let c0 = char_of_int ((v lsr 24) land 0xff)
  and c1 = char_of_int ((v lsr 16) land 0xff)
  and c2 = char_of_int ((v lsr 8) land 0xff)
  and c3 = char_of_int (v land 0xff) in
  let res = String.make 4 c0 in
  res.[1] <- c1;
  res.[2] <- c2;
  res.[3] <- c3;
  res

let value_of_uint32 i = VInt (i, 32, BigEndian)



type uint32le = int

let parse_uint32le input =
  if input.cur_offset + 2 <= input.cur_length then begin
    let res =
      (int_of_char (input.str.[input.cur_base + input.cur_offset + 3]) lsl 24) lor
      (int_of_char (input.str.[input.cur_base + input.cur_offset + 2]) lsl 16) lor
      (int_of_char (input.str.[input.cur_base + input.cur_offset + 1]) lsl 8) lor
	(int_of_char (input.str.[input.cur_base + input.cur_offset]))
    in
    input.cur_offset <- input.cur_offset + 4;
    res
  end else raise (ParsingException (OutOfBounds, _h_of_si input))

let lwt_parse_uint32le input =
  lwt_really_read input 4 >>= fun s ->
  return (((int_of_char s.[3]) lsl 24) lor ((int_of_char s.[2]) lsl 16)
    lor ((int_of_char s.[1]) lsl 8) lor (int_of_char s.[0]))

let dump_uint32le v =
  let c3 = char_of_int ((v lsr 24) land 0xff)
  and c2 = char_of_int ((v lsr 16) land 0xff)
  and c1 = char_of_int ((v lsr 8) land 0xff)
  and c0 = char_of_int (v land 0xff) in
  let res = String.make 4 c0 in
  res.[1] <- c1;
  res.[2] <- c2;
  res.[3] <- c3;
  res

let value_of_uint32le i = VInt (i, 32, LittleEndian)



type uint64le = Int64.t

let parse_uint64le input =
  if input.cur_offset + 2 <= input.cur_length then begin
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

let lwt_parse_uint64le input =
  lwt_really_read input 8 >>= fun s ->
    let r1 = (((int_of_char s.[3]) lsl 24) lor ((int_of_char s.[2]) lsl 16)
      lor ((int_of_char s.[1]) lsl 8) lor (int_of_char s.[0])) in
    let r2 = (((int_of_char s.[7]) lsl 24) lor ((int_of_char s.[6]) lsl 16)
      lor ((int_of_char s.[5]) lsl 8) lor (int_of_char s.[4])) in
    let r = Int64.logor (Int64.shift_left (Int64.of_int r2) 32) (Int64.of_int r1) in
    return r

let dump_uint64le v =
  let open Int64 in
  let ff = of_int 0xff in
  let c7 = char_of_int (to_int (logand (shift_right v 56) ff))
  and c6 = char_of_int (to_int (logand (shift_right v 48) ff))
  and c5 = char_of_int (to_int (logand (shift_right v 40) ff))
  and c4 = char_of_int (to_int (logand (shift_right v 32) ff))
  and c3 = char_of_int (to_int (logand (shift_right v 24) ff))
  and c2 = char_of_int (to_int (logand (shift_right v 16) ff))
  and c1 = char_of_int (to_int (logand (shift_right v 8) ff))
  and c0 = char_of_int (to_int (logand v ff)) in
  let res = String.make 8 c0 in
  res.[1] <- c1;
  res.[2] <- c2;
  res.[3] <- c3;
  res.[4] <- c4;
  res.[5] <- c5;
  res.[6] <- c6;
  res.[7] <- c7;
  res

let value_of_uint64le i = VBigInt (dump_uint64le i, LittleEndian)



(***********)
(* Strings *)
(***********)

let parse_string n input =
  if input.cur_offset + n <= input.cur_length then begin
    let res = String.sub input.str (input.cur_base + input.cur_offset) n in
    input.cur_offset <- input.cur_offset + n;
    res
  end else raise (ParsingException (OutOfBounds, _h_of_si input))

let lwt_parse_string n input = lwt_really_read input n

let parse_rem_string input =
  let res = String.sub input.str (input.cur_base + input.cur_offset) (input.cur_length - input.cur_offset) in
  input.cur_offset <- input.cur_length;
  res

let lwt_parse_rem_string input =
  if input.lwt_rewindable
  then lwt_really_read input (input.lwt_length - input.lwt_offset)
  else fail (ParsingException (NotImplemented "lwt_parse_rem_string", _h_of_li input))


let parse_varlen_string name len_fun input =
  let n = len_fun input in
  let new_input = get_in input name n in
  let res = parse_rem_string new_input in
  get_out input new_input;
  res

let lwt_parse_varlen_string name len_fun input =
  len_fun input >>= fun n ->
  lwt_get_in input name n >>= fun str_input ->
  let res = parse_rem_string str_input in
  lwt_get_out input str_input >>= fun () ->
  return res


let drop_bytes n input =
  if input.cur_offset + n <= input.cur_length
  then input.cur_offset <- input.cur_offset + n
  else raise (ParsingException (OutOfBounds, _h_of_si input))

let lwt_drop_bytes n input =
  lwt_really_read input n >>= fun _ -> return ()

let drop_rem_bytes input =
  input.cur_offset <- input.cur_length

let lwt_drop_rem_bytes input =
  if input.lwt_rewindable then begin
    lwt_really_read input (input.lwt_length - input.lwt_offset) >>= fun _ ->
    return ()
  end else fail (ParsingException (NotImplemented "lwt_drop_rem_bytes", _h_of_li input))


let dump_string s = s

let dump_varlen_string len_fun s =
  let n = String.length s in
  (len_fun n) ^ s

let value_of_string binary s = VString (s, binary)



(**********************)
(* List and container *)
(**********************)

let parse_list n parse_fun input =
  let rec aux accu = function
    | 0 -> List.rev accu
    | i ->
      let x = parse_fun input in
      aux (x::accu) (i-1)
  in aux [] n

let lwt_parse_list n lwt_parse_fun input =
  let rec aux accu = function
    | 0 -> return (List.rev accu)
    | i ->
      lwt_parse_fun input >>= fun x ->
      aux (x::accu) (i-1)
  in aux [] n


let parse_rem_list parse_fun input =
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

let lwt_parse_rem_list lwt_parse_fun input =
  let rec aux accu =
    if lwt_eos input
    then return (List.rev accu)
    else begin
      let saved_offset = input.lwt_offset in
      let finalize_ok x = aux (x::accu)
      and finalize_nok = function
	| ParsingStop ->
	  if input.lwt_rewindable then begin
	    Lwt_io.set_position input.lwt_ch (Int64.of_int saved_offset) >>= fun () ->
	    input.lwt_offset <- saved_offset;
	    return (List.rev accu)
	  end else return (List.rev accu)
	| (ParsingException _) as e ->
	    if input.lwt_offset = saved_offset
	    then return (List.rev accu)
	    else fail e
	| e -> fail e
      in try_bind (fun () -> lwt_parse_fun input) finalize_ok finalize_nok
    end
  in aux []


let parse_varlen_list name len_fun parse_fun input =
  let n = len_fun input in
  let new_input = get_in input name n in
  let res = parse_rem_list parse_fun new_input in
  get_out input new_input;
  res

let lwt_parse_varlen_list name len_fun parse_fun input =
  len_fun input >>= fun n ->
  lwt_get_in input name n >>= fun str_input ->
  wrap2 parse_rem_list parse_fun str_input >>= fun res ->
  lwt_get_out input str_input >>= fun () ->
  return res


let dump_list dump_fun l =
  String.concat "" (List.map dump_fun l)

let dump_varlen_list len_fun dump_fun l =
  let res = dump_list dump_fun l in
  let n = String.length res in
  (len_fun n) ^ res

let value_of_list sub_fun l = VList (List.map sub_fun l)



(*************)
(* Container *)
(*************)

let parse_container name n parse_fun input =
  let new_input = get_in input name n in
  let res = parse_fun new_input in
  get_out input new_input;
  res

let lwt_parse_container name n parse_fun input =
  lwt_get_in input name n >>= fun str_input ->
  wrap1 parse_fun str_input >>= fun res ->
  lwt_get_out input str_input >>= fun () ->
  return res

let dump_container len_fun dump_fun content =
  let res = dump_fun content in
  let n = String.length res in
  (len_fun n) ^ res


let parse_varlen_container name len_fun parse_fun input =
  let n = len_fun input in
  parse_container name n parse_fun input

let lwt_parse_varlen_container name len_fun parse_fun input =
  len_fun input >>= fun n ->
  lwt_parse_container name n parse_fun input



(*********)
(* Array *)
(*********)

let parse_array n parse_fun input =
  Array.init n (fun _ -> parse_fun input)

(* TODO: Is it possible to do better? *)
let lwt_parse_array n lwt_parse_fun input =
  lwt_parse_list n lwt_parse_fun input >>= fun l ->
  return (Array.of_list l)

let dump_array dump_fun a =
  String.concat "" (Array.to_list (Array.map dump_fun a))

let value_of_array sub_fun a = VList (List.map sub_fun (Array.to_list a))
