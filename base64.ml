open Parsifal
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


(* TODO: Avoid using a custom exception *)
exception InvalidBase64String of string

let to_raw_base64 s =
  let n = String.length s in
  let n_groups = (n+2) / 3 in
  let res = String.make (n_groups * 4) '=' in

  let rec get_next_group i =
    match n - i with
      | 0 -> 0, 0
      | 1 -> (int_of_char (s.[i]) lsl 16), 2
      | 2 ->
	(int_of_char (s.[i]) lsl 16) lor
	  (int_of_char (s.[i+1]) lsl 8), 3
      | _ ->
	(int_of_char (s.[i]) lsl 16) lor
	  (int_of_char (s.[i+1]) lsl 8) lor
	  (int_of_char (s.[i+2])), 4
  in

  let encode_group dest_i v significant_bytes =
    let rec encode_aux v k =
      if k < significant_bytes
      then res.[dest_i + k] <- base64_chars.[v land 63];
      if (k>0) then encode_aux (v lsr 6) (k-1)
    in
    encode_aux v 3
  in

  for i = 0 to n_groups - 1 do
    let group, significant_bytes = get_next_group (i*3) in
    encode_group (i*4) group significant_bytes;
  done;
  res


let from_raw_base64 s =
  let n = String.length s in
  if n mod 4 <> 0 then raise (InvalidBase64String "Wrong length");
  let n_groups = n/4 in
  let to_drop, entire_groups =
    if s.[n-1] = '=' then begin
      (if s.[n-2] = '=' then 2 else 1), n_groups - 1
    end else 0, n_groups
  in
  let decoded_len = (n_groups * 3) - to_drop in
  let res = String.make decoded_len '\x00' in
  
  for i = 0 to entire_groups - 1 do
    let v1 = reverse_base64_chars.(int_of_char (s.[i * 4]))
    and v2 = reverse_base64_chars.(int_of_char (s.[i * 4 + 1]))
    and v3 = reverse_base64_chars.(int_of_char (s.[i * 4 + 2]))
    and v4 = reverse_base64_chars.(int_of_char (s.[i * 4 + 3])) in
    res.[i * 3] <- char_of_int ((v1 lsl 2) lor (v2 lsr 4));
    res.[i * 3 + 1] <- char_of_int (((v2 land 0xf) lsl 4) lor (v3 lsr 2));
    res.[i * 3 + 2] <- char_of_int (((v3 land 0x3) lsl 6) lor v4)
  done;

  begin
    match to_drop with
      | 1 ->
	let v1 = reverse_base64_chars.(int_of_char (s.[n - 4]))
	and v2 = reverse_base64_chars.(int_of_char (s.[n - 3]))
	and v3 = reverse_base64_chars.(int_of_char (s.[n - 2])) in
	res.[decoded_len - 2] <- char_of_int ((v1 lsl 2) lor (v2 lsr 4));
	res.[decoded_len - 1] <- char_of_int (((v2 land 0xf) lsl 4) lor (v3 lsr 2));
      | 2 ->
	let v1 = reverse_base64_chars.(int_of_char (s.[n - 4]))
	and v2 = reverse_base64_chars.(int_of_char (s.[n - 3])) in
	res.[decoded_len - 1] <- char_of_int ((v1 lsl 2) lor (v2 lsr 4));
      | _ -> ()
  end;
  res;;


let to_base64 title s =
  let mk_boundary header =
    if header
    then "-----BEGIN " ^ title ^ "-----\n"
    else "\n-----END " ^ title ^ "-----"
  and cut_at l s =
    let rec cut_at_aux accu remaining start =
      if remaining > l
      then cut_at_aux ((String.sub s start l)::accu) (remaining - l) (start + l)
      else List.rev ((String.sub s start remaining)::accu)
    in cut_at_aux [] (String.length s) 0
  in

  (mk_boundary true) ^
    (String.concat "\n" (cut_at 64 (to_raw_base64 s))) ^
    (mk_boundary false)



let from_base64 title input =
  let rec next_nonblank input =
    let c = parse_uint8 input in
    if reverse_base64_chars.(c) = -2
    then next_nonblank input
    else c
  in

  let rec debaser b b64chunk input =
    let v = next_nonblank input in
    if v >= -1 
    then begin
      match v::b64chunk with
      | [-1; -1; v2; v1] -> 
	Buffer.add_char b (char_of_int ((v1 lsl 2) lor (v2 lsr 4)))
      | [-1; v3; v2; v1] ->
	Buffer.add_char b (char_of_int ((v1 lsl 2) lor (v2 lsr 4)));
	Buffer.add_char b (char_of_int (((v2 land 0xf) lsl 4) lor (v3 lsr 2)))
      | [v4; v3; v2; v1] ->
	Buffer.add_char b (char_of_int ((v1 lsl 2) lor (v2 lsr 4)));
	Buffer.add_char b (char_of_int (((v2 land 0xf) lsl 4) lor (v3 lsr 2)));
	Buffer.add_char b (char_of_int (((v3 land 0x3) lsl 6) lor v4));
	debaser b [] input
      | new_chunk -> debaser b new_chunk input
    end else raise (InvalidBase64String "Invalid character")
  in

  let rec read_until_dash b input =
    let c = parse_char input in
    if c <> '-' then begin
      Buffer.add_char b c;
      read_until_dash b input
    end
  in

  let read_title header input =
    let c = next_nonblank input in
    if char_of_int c <> '-'
    then raise (InvalidBase64String "Invalid character");
    let title = Buffer.create 32 in
    if header
    then parse_magic "----BEGIN " input
    else parse_magic "----END " input;
    read_until_dash title input;
    parse_magic "----" input;
    Buffer.contents title
  in

  let res = Buffer.create 1024 in
  let t1 = read_title true input in
  debaser res [] input;
  let t2 = read_title false input in
  match title, t1 = t2 with
  | None, true -> Buffer.contents res
  | Some t, true ->
    if not (List.mem t1 t)
    then raise (InvalidBase64String (t1 ^ " expected, " ^ t2 ^ " found"))
    else Buffer.contents res
  | _, false ->
    raise (InvalidBase64String ("inconsistent titles"))


let lwt_from_base64 title input =
  let rec next_nonblank input =
    lwt_parse_uint8 input >>= fun c ->
    if reverse_base64_chars.(c) = -2
    then next_nonblank input
    else return c
  in

  let rec debaser b b64chunk input =
    next_nonblank input >>= fun c ->
    let v = reverse_base64_chars.(c) in
    if v >= -1
    then begin
      match v::b64chunk with
      | [-1; -1; v2; v1] -> 
	Buffer.add_char b (char_of_int ((v1 lsl 2) lor (v2 lsr 4)));
	return ()
      | [-1; v3; v2; v1] ->
	Buffer.add_char b (char_of_int ((v1 lsl 2) lor (v2 lsr 4)));
	Buffer.add_char b (char_of_int (((v2 land 0xf) lsl 4) lor (v3 lsr 2)));
	return ()
      | [v4; v3; v2; v1] ->
	Buffer.add_char b (char_of_int ((v1 lsl 2) lor (v2 lsr 4)));
	Buffer.add_char b (char_of_int (((v2 land 0xf) lsl 4) lor (v3 lsr 2)));
	Buffer.add_char b (char_of_int (((v3 land 0x3) lsl 6) lor v4));
	debaser b [] input
      | new_chunk -> debaser b new_chunk input
    end else fail (InvalidBase64String "Invalid character")
  in

  let rec read_until_dash b input =
    lwt_parse_char input >>= fun c ->
    if c <> '-' then begin
      Buffer.add_char b c;
      read_until_dash b input
    end else return ()
  in

  let read_title header input =
    next_nonblank input >>= fun c ->
    if char_of_int c <> '-'
    then fail (InvalidBase64String "Invalid character")
    else begin
      let title = Buffer.create 32 in
      (if header
      then lwt_parse_magic "----BEGIN "
      else lwt_parse_magic "----END ") input >>= fun () ->
      read_until_dash title input >>= fun () ->
      lwt_parse_magic "----" input >>= fun () ->
      return (Buffer.contents title)
    end
  in

  let res = Buffer.create 1024 in
  read_title true input >>= fun t1 ->
  debaser res [] input >>= fun () ->
  read_title false input >>= fun t2 ->
  match title, t1 = t2 with
  | None, true ->
    return (Buffer.contents res)
  | Some t, true ->
    if not (List.mem t1 t)
    then fail (InvalidBase64String (t1 ^ " expected, " ^ t2 ^ " found"))
    else return (Buffer.contents res)
  | _, false ->
    fail (InvalidBase64String ("inconsistent titles"))


let parse_base64_container title parse_fun input =
  let content = from_base64 title input in
  let new_input = {
    (input_of_string "base64_container" content) with
      history = (input.cur_name, input.cur_offset, Some input.cur_length)::input.history;
      enrich = input.enrich
  } in
  let res = parse_fun new_input in
  check_empty_input true new_input;
  res

let lwt_parse_base64_container title parse_fun input =
  lwt_from_base64 title input >>= fun content ->
  let new_input = {
    (input_of_string "base64_container" content) with
      history = [input.lwt_name, input.lwt_offset, None];
      enrich = input.lwt_enrich
  } in
  let res = parse_fun new_input in
  check_empty_input true new_input;
  return res

let dump_base64_container title dump_fun o =
  let content = dump_fun o in
  to_base64 title content
