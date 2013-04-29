open Parsifal
open BasePTypes
open PTypes
open Lwt

let base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

(* How to interpret the following array:
   - 0-63 => real base64 chars
   - -1 is for the '=' char (terminator)
   - -2 is for blank chars
   - -3 is for the rest (if we want to be strict one day)
*)
let reverse_base64_chars =
  [|-3; -3; -3; -3; -3; -3; -3; -3; -3; -2; -2; -3; -3; -2; -3; -3;
    -3; -3; -3; -3; -3; -3; -3; -3; -3; -3; -3; -3; -3; -3; -3; -3;
    -2; -3; -3; -3; -3; -3; -3; -3; -3; -3; -3; 62; -3; -3; -3; 63;
    52; 53; 54; 55; 56; 57; 58; 59; 60; 61; -3; -3; -3; -1; -3; -3;
    -3; 00; 01; 02; 03; 04; 05; 06; 07; 08; 09; 10; 11; 12; 13; 14;
    15; 16; 17; 18; 19; 20; 21; 22; 23; 24; 25; -3; -3; -3; -3; -3;
    -3; 26; 27; 28; 29; 30; 31; 32; 33; 34; 35; 36; 37; 38; 39; 40;
    41; 42; 43; 44; 45; 46; 47; 48; 49; 50; 51; -3; -3; -3; -3; -3;
    -3; -3; -3; -3; -3; -3; -3; -3; -3; -3; -3; -3; -3; -3; -3; -3;
    -3; -3; -3; -3; -3; -3; -3; -3; -3; -3; -3; -3; -3; -3; -3; -3;
    -3; -3; -3; -3; -3; -3; -3; -3; -3; -3; -3; -3; -3; -3; -3; -3;
    -3; -3; -3; -3; -3; -3; -3; -3; -3; -3; -3; -3; -3; -3; -3; -3;
    -3; -3; -3; -3; -3; -3; -3; -3; -3; -3; -3; -3; -3; -3; -3; -3;
    -3; -3; -3; -3; -3; -3; -3; -3; -3; -3; -3; -3; -3; -3; -3; -3;
    -3; -3; -3; -3; -3; -3; -3; -3; -3; -3; -3; -3; -3; -3; -3; -3;
    -3; -3; -3; -3; -3; -3; -3; -3; -3; -3; -3; -3; -3; -3; -3; -3|]


type header_expected =
  | NoHeader
  | AnyHeader
  | HeaderInList of string list

let raiseB64 s i =
  let h = _h_of_si i in
  raise (ParsingException (InvalidBase64String s, h))

let lwt_raiseB64 s i =
  let h = _h_of_li i in
  fail (ParsingException (InvalidBase64String s, h))



(* Useful real base64 funs *)

let decode_rev_chunk b = function
  | [-1; -1; v2; v1] -> 
    Buffer.add_char b (char_of_int ((v1 lsl 2) lor (v2 lsr 4)));
    None
  | [-1; v3; v2; v1] ->
    Buffer.add_char b (char_of_int ((v1 lsl 2) lor (v2 lsr 4)));
    Buffer.add_char b (char_of_int (((v2 land 0xf) lsl 4) lor (v3 lsr 2)));
    None
  | [v4; v3; v2; v1] ->
    Buffer.add_char b (char_of_int ((v1 lsl 2) lor (v2 lsr 4)));
    Buffer.add_char b (char_of_int (((v2 land 0xf) lsl 4) lor (v3 lsr 2)));
    Buffer.add_char b (char_of_int (((v3 land 0x3) lsl 6) lor v4));
    Some []
  | new_chunk -> Some new_chunk


let rec debaser b b64chunk input =
  if eos input then ()
  else begin
    let c = drop_while (fun c -> reverse_base64_chars.(c) = -2) input in
    let v = reverse_base64_chars.(c) in
    if v >= -1
    then begin
      match decode_rev_chunk b (v::b64chunk) with
      | None -> ()
      | Some new_chunk -> debaser b new_chunk input
    end else raiseB64 "Invalid character" input
  end

let rec lwt_debaser b b64chunk lwt_input =
  lwt_drop_while (fun c -> reverse_base64_chars.(c) = -2) lwt_input >>= fun c ->
  let v = reverse_base64_chars.(c) in
  if v >= -1 
  then begin
    match decode_rev_chunk b (v::b64chunk) with
    | None -> return ()
    | Some new_chunk -> lwt_debaser b new_chunk lwt_input
  end else lwt_raiseB64 "Invalid character" lwt_input



let string_of_base64_title title input =
  let read_title header input =
    let c = drop_while (fun c -> reverse_base64_chars.(c) = -2) input in
    if char_of_int c <> '-'
    then raiseB64 "Dash expected" input;
    ignore (parse_magic (if header then "----BEGIN " else "----END ") input);
    let title = read_while (fun c -> c <> (int_of_char '-')) input in
    ignore (parse_magic "----" input);
    title
  in

  let res = Buffer.create 1024 in
  let t1 = read_title true input in
  debaser res [] input;
  let t2 = read_title false input in
  match title, t1 = t2 with
  | None, true -> Buffer.contents res
  | Some t, true ->
    if not (List.mem t1 t)
    then raiseB64 (List.hd t ^ " expected, " ^ t1 ^ " found") input
    else Buffer.contents res
  | _, false -> raiseB64 "inconsistent titles" input


let lwt_string_of_base64_title title lwt_input =
  let lwt_read_title header lwt_input =
    lwt_drop_while (fun c -> reverse_base64_chars.(c) = -2) lwt_input >>= fun c ->
    if char_of_int c <> '-'
    then lwt_raiseB64 "Dash expected" lwt_input
    else begin
      lwt_parse_magic (if header then  "----BEGIN " else "----END ") lwt_input >>= fun _ ->
      lwt_read_while (fun c -> c <> (int_of_char '-')) lwt_input >>= fun title ->
      lwt_parse_magic "----" lwt_input >>= fun _ ->
      return title
    end
  in

  let res = Buffer.create 1024 in
  lwt_read_title true lwt_input >>= fun t1 ->
  lwt_debaser res [] lwt_input >>= fun () ->
  lwt_read_title false lwt_input >>= fun t2 ->
  match title, t1 = t2 with
  | None, true ->
    return (Buffer.contents res)
  | Some t, true ->
    if not (List.mem t1 t)
    then lwt_raiseB64 (List.hd t ^ " expected, " ^ t1 ^ " found") lwt_input
    else return (Buffer.contents res)
  | _, false -> lwt_raiseB64 "inconsistent titles" lwt_input



let to_raw_base64 maxlen buf bin_buf =
  let n = Buffer.length bin_buf in
  let rec add_group = function
    | v::r, padding_needed ->
      Buffer.add_char buf base64_chars.[v];
      add_group (r, padding_needed)
    | [], 0 -> ()
    | [], padding_needed ->
      Buffer.add_char buf '=';
      add_group ([], padding_needed - 1)
  in
  let rec handle_next_group i rem =
    match rem with
      | 0 -> ()
      | 1 ->
	let v1 = int_of_char (Buffer.nth bin_buf i) in
	add_group ([v1 lsr 2;
		    (v1 lsl 4) land 0x3f], 2)
      | 2 ->
	let v1 = int_of_char (Buffer.nth bin_buf i)
	and v2 = int_of_char (Buffer.nth bin_buf (i+1)) in
	add_group ([v1 lsr 2;
		    ((v1 lsl 4) land 0x3f) lor (v2 lsr 4);
		    (v2 lsl 2) land 0x3f], 1)
      | _ ->
	let v1 = int_of_char (Buffer.nth bin_buf i)
	and v2 = int_of_char (Buffer.nth bin_buf (i+1))
	and v3 = int_of_char (Buffer.nth bin_buf (i+2)) in
	add_group ([v1 lsr 2;
		    ((v1 lsl 4) land 0x3f) lor (v2 lsr 4);
		    ((v2 lsl 2) land 0x3f) lor (v3 lsr 6);
		    v3 land 0x3f], 0);
	let new_i = i+3 and new_rem = rem -3 in
	if maxlen > 0 && (new_i mod maxlen == 0) then Buffer.add_char buf '\n';
	handle_next_group new_i new_rem
  in
  handle_next_group 0 n


let to_base64 title buf bin_buf =
  let mk_boundary t header =
    Buffer.add_string buf (if header then "-----BEGIN " else "\n-----END ");
    Buffer.add_string buf t;
    Buffer.add_string buf "-----\n"
  in
  match title with
  | HeaderInList [t] ->
    mk_boundary t true;
    to_raw_base64 48 buf bin_buf;
    mk_boundary t false
  | HeaderInList _
  | AnyHeader
  | NoHeader -> to_raw_base64 0 buf bin_buf



(* Base64 container *)

type 'a base64_container = 'a

let parse_base64_container header_expected parse_fun input =
  let content = match header_expected with
    | NoHeader ->
      let res = Buffer.create 1024 in
      debaser res [] input;
      Buffer.contents res
    | AnyHeader -> string_of_base64_title None input
    | HeaderInList l -> string_of_base64_title (Some l) input
  in
  let new_input = {
    (input_of_string "base64_container" content) with
      history = (input.cur_name, input.cur_offset, Some input.cur_length)::input.history;
      enrich = input.enrich
  } in
  let res = parse_fun new_input in
  check_empty_input true new_input;
  res

let lwt_parse_base64_container title parse_fun lwt_input =
  begin
    match title with
    | NoHeader ->
      let res = Buffer.create 1024 in
      lwt_debaser res [] lwt_input >>= fun () ->
      return (Buffer.contents res)
    | AnyHeader -> lwt_string_of_base64_title None lwt_input
    | HeaderInList l -> lwt_string_of_base64_title (Some l) lwt_input
  end >>= fun content ->
  let new_input = {
    (input_of_string "base64_container" content) with
      history = [lwt_input.lwt_name, lwt_input.lwt_offset, None];
      enrich = lwt_input.lwt_enrich
  } in
  let res = parse_fun new_input in
  check_empty_input true new_input;
  return res

let dump_base64_container title dump_fun buf o =
  let tmp_buf = Buffer.create !default_buffer_size in
  dump_fun tmp_buf o;
  to_base64 title buf tmp_buf

let value_of_base64_container = value_of_container
