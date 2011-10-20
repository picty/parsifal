exception IntegerOverflow
exception FormatError

let identity x = x


(* String functions *)

let hexa_char = [| '0'; '1'; '2'; '3';
		   '4'; '5'; '6'; '7';
		   '8'; '9'; 'a'; 'b';
		   'c'; 'd'; 'e'; 'f' |]

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

let hexdump s =
  let len = String.length s in
  let res = String.make (len * 2) ' ' in
  for i = 0 to (len - 1) do
    let x = int_of_char (String.get s i) in
    res.[i * 2] <- hexa_char.((x lsr 4) land 0xf);
    res.[i * 2 + 1] <- hexa_char.(x land 0xf);
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
      res.[pos] <- hexa_char.(i land 0xf);
      aux (i lsr 4) (pos - 1)
  in
  aux x (len - 1);
  res

let hexdump_int_list x =
  let len = List.length x in
  let res = String.make (len * 2) ' ' in
  let rec aux pos = function
    | [] -> ()
    | i::r ->
      res.[pos] <- hexa_char.((i lsr 4) land 0xf);
      res.[pos + 1] <- hexa_char.(i land 0xf);
      aux (pos + 2) r
  in
  aux 0 x;
  res

let pop_int s offset n =
  let content = String.sub s offset n in
  try
    Some (int_of_string content)
  with
      Failure "int_of_string" -> None

let string_of_ip ip  =
  (string_of_int ip.(0)) ^ "." ^
  (string_of_int ip.(1)) ^ "." ^
  (string_of_int ip.(2)) ^ "." ^
  (string_of_int ip.(3))


(* Stream functions *)

let eos stream =
  try
    Stream.empty stream;
    true
  with Stream.Failure -> false

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
  with Stream.Failure -> !res
  

(* Triplet functions *)

let fst3 (a, _, _) = a
let snd3 (_, b, _) = b
let trd3 (_, _, c) = c
