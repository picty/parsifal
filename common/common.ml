exception NotFound of string
exception IntegerOverflow
exception FormatError


type ('a, 'b) alternative =
  | Left of 'a
  | Right of 'b



let identity x = x


(* String functions *)

let hexa_char = "0123456789abcdef"

let only_ascii s =
  let len = String.length s in
  let res = String.make len ' ' in
  for i = 0 to (len - 1) do
    let c = String.get s i in
    let x = int_of_char c in
    if x >= 32 && x < 128
    then res.[i] <- c
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


let hexdump s =
  let len = String.length s in
  let res = String.make (len * 2) ' ' in
  for i = 0 to (len - 1) do
    let x = int_of_char (String.get s i) in
    res.[i * 2] <- hexa_char.[(x lsr 4) land 0xf];
    res.[i * 2 + 1] <- hexa_char.[x land 0xf];
  done;
  res

let hexparse s =
  let len = String.length s in
  if len mod 2 = 1 then raise FormatError else begin
    try
      let res = String.make (len / 2) ' ' in
      for i = 0 to ((len / 2) - 1) do
	res.[i] <- char_of_int (int_of_string ("0x" ^ String.sub s (i * 2) 2))
      done;
      res
    with Failure "int_of_string" -> raise FormatError
  end


let hexdump_int len x =
  let res = String.make len ' ' in
  let rec aux i pos = match pos with
    | -1 ->
      if i <> 0
      then raise IntegerOverflow
    | _ ->
      res.[pos] <- hexa_char.[i land 0xf];
      aux (i lsr 4) (pos - 1)
  in
  aux x (len - 1);
  res

let string_of_int_list l =
  let n = List.length l in
  let res = String.make n ' ' in
  let rec aux pos = function
    | [] -> res
    | c::r ->
      res.[pos] <- char_of_int (c);
      aux (pos + 1) r
  in aux 0 l


let pop_int s offset n =
  let content = String.sub s offset n in
  try
    Some (int_of_string content)
  with
      Failure "int_of_string" -> None

let pop_option x def =
  match x with
    | None -> def
    | Some v -> v


let string_of_ip4 ip4 =
  (string_of_int (int_of_char ip4.[0])) ^ "." ^
  (string_of_int (int_of_char ip4.[1])) ^ "." ^
  (string_of_int (int_of_char ip4.[2])) ^ "." ^
  (string_of_int (int_of_char ip4.[3]))

let string_of_ip6 ip6 =
  if String.length ip6 <> 16 then failwith "Invalid IPv6 address";
  let res = String.make (32+7) ':' in
  let rec aux src dst =
    if src > 15 then res
    else begin
      res.[dst] <- hexa_char.[((int_of_char ip6.[src]) lsr 4) land 0xf];
      res.[dst+1] <- hexa_char.[(int_of_char ip6.[src]) land 0xf];
      res.[dst+2] <- hexa_char.[((int_of_char ip6.[src + 1]) lsr 4) land 0xf];
      res.[dst+3] <- hexa_char.[(int_of_char ip6.[src + 1]) land 0xf];
      aux (src+2) (dst+5)
    end
  in aux 0 0


let string_split c s =
  let rec aux offset =
    try
      let next_index = String.index_from s offset c in
      (String.sub s offset (next_index - offset))::(aux (next_index + 1))
    with Not_found ->
      let len = String.length s in
      if offset < len then [String.sub s offset (len - offset)] else []
  in aux 0

let ip4_of_string s =
  let res = String.make 4 ' ' in
  let rec aux = function
    | i, elt::r when i <= 3 ->
      res.[i] <- char_of_int elt;
      aux (i+1, r)
    | 4, [] -> res
    | _ -> failwith "Invalid IP";
  in aux (0, List.map int_of_string (string_split '.' s))



let dump_uint32 x =
  string_of_int_list [(x lsr 24) land 0xff; (x lsr 16) land 0xff;
		      (x lsr 8) land 0xff; x land 0xff]

let dump_uint24 x =
  string_of_int_list [(x lsr 16) land 0xff; (x lsr 8) land 0xff; x land 0xff]

let dump_uint16 x =
  if x > 65535 then failwith "Integer overflow";
  string_of_int_list [x lsr 8; x land 0xff]

let dump_uint8 x =
  if x > 255 then failwith "Integer overflow";
  String.make 1 (char_of_int x)


let dump_variable_length_string length_fun s =
  let len = String.length s in
  (length_fun len) ^ s




(* Stream functions *)

let eos stream =
  try
    Stream.empty stream;
    true
  with
    | Sys_blocked_io -> true
    | Stream.Failure -> false

let pop_line stream =
  let res = ref "" in
  let rec pop_char () =
    let next_char = Stream.next stream in
    if next_char = '\n'
    then !res
    else begin
      res := (!res) ^ (String.make 1 next_char);
      pop_char ()
    end
  in
  try
    pop_char ()
  with Sys_blocked_io | Stream.Failure -> !res
  

(* Triplet functions *)

let fst3 (a, _, _) = a
let snd3 (_, b, _) = b
let trd3 (_, _, c) = c


(* Hashtable functions *)

let hash_find_default ht name def =
  try Hashtbl.find ht name
  with Not_found -> def

let hash_find ht name =
  try Hashtbl.find ht name
  with Not_found -> raise (NotFound name)

let (-->) = hash_find
