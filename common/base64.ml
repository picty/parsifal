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
  let dashes = "-----" in
  let mk_boundary header =
    match title with
      | None -> ""
      | Some title ->
	if header
	then dashes ^ "BEGIN " ^ title ^ dashes ^ !Common.endline
	else !Common.endline ^ dashes ^ "END " ^ title ^ dashes
  in
  (mk_boundary true) ^
    (Common.cat (Common.string_cut_at 64 (to_raw_base64 s))) ^
    (mk_boundary false)


let from_base64 expected_title s =

  let decapsulate is_begin l =
    let l_len = String.length l in
    let start_str = if is_begin then "-----BEGIN " else "-----END " in
    let start_len = String.length start_str in
    if (l_len > start_len) && (String.sub l 0 start_len) = start_str && (String.sub l (l_len - 5) 5) = "-----"
    then Some (String.sub l start_len (l_len - 5 - start_len))
    else None
  in

  let title, content = match Common.string_split '\n' s with
    | first::rest -> begin
      match (List.rev rest) with
	| last::rev_content -> begin
	  match decapsulate true first, decapsulate false last with
	    | Some t1, Some t2 when t1 = t2 -> Some t1, (String.concat "" (List.rev rev_content))
	    | None, None -> None, s
	    | _ -> raise (InvalidBase64String "Wrong title header or tailer")
	end
	| _ -> None, s
    end
    | _ -> None, s
  in

  begin
    match expected_title, title with
      | None, _ -> ()
      | Some t1, None -> raise (InvalidBase64String (t1 ^ " expected"))
      | Some t1, Some t2 when t1 = t2 -> ()
      | Some t1, Some t2 -> raise (InvalidBase64String (t1 ^ " expected, " ^ t2 ^ " found"))
  end;
  
  let n = String.length content in
  let tmp = String.make n '\x00' in

  let rec keep_only_b64_chars src_i dst_i =
    if src_i >= n then dst_i
    else begin
      let c = content.[src_i] in
      if reverse_base64_chars.(int_of_char c) >= -1
      then begin
	tmp.[dst_i] <- c;
	keep_only_b64_chars (src_i + 1) (dst_i + 1)
      end else 
	keep_only_b64_chars (src_i + 1) (dst_i)
    end
  in

  let real_n = keep_only_b64_chars 0 0 in
  from_raw_base64 (String.sub tmp 0 real_n)
