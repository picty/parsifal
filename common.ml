exception NotImplemented of string


let pop_opt default = function
  | None -> default
  | Some x -> x


let hexa_char = "0123456789abcdef"

let hexdump s =
  let len = String.length s in
  let res = String.make (len * 2) ' ' in
  for i = 0 to (len - 1) do
    let x = int_of_char (String.get s i) in
    res.[i * 2] <- hexa_char.[(x lsr 4) land 0xf];
    res.[i * 2 + 1] <- hexa_char.[x land 0xf];
  done;
  res


let quote_string s =
  let n = String.length s in

  let estimate_len_char c =
    match c with
      | '\n' | '\t' | '\\' | '"' -> 2
      | c -> let x = int_of_char c in
	     if x >= 32 && x < 128 then 1 else 4
  in
  let rec estimate_len accu offset =
    if offset = n then accu
    else estimate_len (accu + estimate_len_char (s.[offset])) (offset + 1)
  in

  let newlen = estimate_len 0 0 in
  let res = String.make newlen ' ' in

  let mk_two_char c offset =
    res.[offset] <- '\\';
    res.[offset + 1] <- c;
    offset + 2
  in
  let write_char c offset =
    match c with
      | '\n' -> mk_two_char 'n' offset
      | '\t' -> mk_two_char 't' offset
      | '\\' -> mk_two_char '\\' offset
      | '"' -> mk_two_char '"' offset
      | c ->
	let x = int_of_char c in
	if x >= 32 && x < 128
	then begin
	  res.[offset] <- c;
	  offset + 1
	end else begin
	  res.[offset] <- '\\';
	  res.[offset + 1] <- 'x';
	  res.[offset + 2] <- hexa_char.[x lsr 4];
	  res.[offset + 3] <- hexa_char.[x land 15];
	  offset + 4
	end
  in
  let rec write_string src_offset dst_offset =
    if src_offset < n then begin
      let new_offset = write_char s.[src_offset] dst_offset in
      write_string (src_offset + 1) (new_offset)
    end
  in
  write_string 0 0;
  res


let hash_get ht k default =
  try Hashtbl.find ht k
  with Not_found -> default
