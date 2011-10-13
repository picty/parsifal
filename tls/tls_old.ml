(* TLS Parser *)

let at s o = int_of_char (String.get s o)

let intlist_of_string s =
  let rec aux accu offset = function
    | 0 -> List.rev accu
    | n -> aux ((at s offset)::accu) (offset + 1) (n - 1)
  in
  aux [] 0 (String.length s)
    
let int32_of_intlist l =
  let rec aux accu = function
    | [] -> accu
    | d::r -> aux (Int32.logor (Int32.of_int d) (Int32.shift_right accu 8)) r
  in aux Int32.zero l

let int32_of_string str offset =
  int32_of_intlist (intlist_of_string String.sub str offset 4)


(* Types *)

type version = int * int
let parse_version str offset =
  let res = (at str offset), (at str (offset + 1)) in
  res, (offset + 2)
  
type random = { gmt_unix_time : int32; random_bytes : string }
let parse_random str offset =
  let ts = int32_of_string str offset in
  let rnd = String.sub str (offset + 4) 28 in
  ({ gmt_unix_time = ts; random_bytes = rnd; }, offset + 32)

type compression_method =
  | CM_Null
  | CM_ZLib
  | CM_Other of int
let compression_method_map =
  [| CM_Null; CM_ZLib |]
let parse_compression_method str offset =
  let x = at str offset in
  if x < Array.length compression_method_map
  then (compression_method_map.(x), offset + 1)
  else (CM_Other x, offset + 1)

type cipher_suite =
  | TLS_NULL_WITH_NULL_NULL
  | TLS_RSA_WITH_NULL_MD5
  | CS_ByStandard of int * int
  | CS_BySpec of int * int
  | CS_Private of int
let cipher_suite_00_map =
  [| TLS_NULL_WITH_NULL_NULL; TLS_RSA_WITH_NULL_MD5 |]
let parse_cipher_suite str offset =
  let x = at str offset in
  let y = at str (offset + 1) in
  if x == 0 && x < Array.length cipher_suite_00_map
  then (cipher_suite_00_map.(x), offset + 2)
  else if x < 0xC0
  then (CS_ByStandard (x, y), offset + 2)
  else if x != 0xff
  then (CS_BySpec (x, y), offset + 2)
  else (CS_Private y, offset + 2)

type tls_extension =
  | Other of int * string

type clientHello = {
  protocol_version : version;
  random : random;
  session_id : string;
  cipher_suites : cipher_suite list;
  compression_methods : compression_method list;
  extensions : tls_extension list;
}

type serverHello = {
  protocol_version : version;
  random : random;
  session_id : string;
  cipher_suites : cipher_suite;
  compression_methods : compression_method;
  extensions : tls_extension list;
}

type 

type handshake_msg =
  | ClientHello of

type tls_record = 
