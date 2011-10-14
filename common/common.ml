exception IntegerOverflow

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

let two_hundred_fifty_six = Big_int.big_int_of_int 256

let hexdump_bigint bi =
  let rec intlist_of_bigint bi =
    if Big_int.eq_big_int bi Big_int.zero_big_int then []
    else
      let q, r = Big_int.quomod_big_int bi two_hundred_fifty_six in
      (Big_int.int_of_big_int r)::(intlist_of_bigint q)
  in
  let l = intlist_of_bigint bi in
  let len = List.length l in
  let res = String.make (len * 2) ' ' in
  let rec write_string offset = function
    | [] -> ()
    | x::r ->
      res.[offset] <- hexa_char.((x lsr 4) land 0xf);
      res.[offset + 1] <- hexa_char.(x land 0xf);
      write_string (offset + 2) r
  in
  write_string 0 l;
  res



let identity x = x



let pop_int s offset n =
  let content = String.sub s offset n in
  try
    Some (int_of_string content)
  with
      Failure "int_of_string" -> None
