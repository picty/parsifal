(* Integer dumping *)

let dump_uint8 v = String.make 1 (char_of_int (v land 0xff))

let dump_char c = String.make 1 c

let dump_uint16 v =
  let c0 = char_of_int ((v lsr 8) land 0xff)
  and c1 = char_of_int (v land 0xff) in
  let res = String.make 2 c0 in
  res.[1] <- c1;
  res

let dump_uint24 v =
  let c0 = char_of_int ((v lsr 16) land 0xff)
  and c1 = char_of_int ((v lsr 8) land 0xff)
  and c2 = char_of_int (v land 0xff) in
  let res = String.make 3 c0 in
  res.[1] <- c1;
  res.[2] <- c2;
  res

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


(* String dumping *)

let dump_string s = s

let dump_varlen_string len_fun s =
  let n = String.length s in
  (len_fun n) ^ s


(* List dumping *)

let dump_list dump_fun l =
  String.concat "" (List.map dump_fun l)

let dump_varlen_list len_fun dump_fun l =
  let n = List.length l in
  (len_fun n) ^ (dump_list dump_fun l)
