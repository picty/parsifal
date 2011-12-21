(* C functions *)

external md5sum : string -> string = "md5sum"
external sha1sum : string -> string = "sha1sum"
external sha224_256sum : string -> bool -> string = "sha224_256sum"
external sha384_512sum : string -> bool -> string = "sha384_512sum"
external aes_cbc : bool -> string -> string -> string -> string = "aes_cbc"

external exp_mod : string -> string -> string -> string = "exp_mod"


(* Exception for the crypto code *)
exception IncorrectPadding


(* Hash functions and HMAC *)

let sha224sum s = sha224_256sum s true
let sha256sum s = sha224_256sum s false
let sha384sum s = sha384_512sum s true
let sha512sum s = sha384_512sum s false

type hash_function = {
  hash_name : string;
  hash_block_size : int;
  hash_len : int;
  hash_fun : string -> string;
}

let mk_hf n blen f = {hash_name = n; hash_block_size = blen; hash_len = String.length (f ""); hash_fun = f}

let hmac hash_fun k m =
  let ipad = String.make hash_fun.hash_block_size '\x36' in
  let opad = String.make hash_fun.hash_block_size '\x5c' in
  let key_length = String.length k in
  let real_key =
    if key_length > hash_fun.hash_block_size
    then hash_fun.hash_fun k
    else k ^ (String.make (hash_fun.hash_block_size - key_length) '\x00')
  in
  for i = 0 to (hash_fun.hash_block_size - 1) do
    ipad.[i] <- char_of_int ((int_of_char ipad.[i]) lxor (int_of_char real_key.[i]));
    opad.[i] <- char_of_int ((int_of_char opad.[i]) lxor (int_of_char real_key.[i]));
  done;
  hash_fun.hash_fun (opad ^ (hash_fun.hash_fun (ipad ^ m)))


let sha1 = mk_hf "sha1" 64 sha1sum
let md5 = mk_hf "md5" 64 md5sum
let sha256 = mk_hf "sha256" 64 sha256sum
let sha224 = mk_hf "sha224" 64 sha224sum
let sha512 = mk_hf "sha512" 128 sha512sum
let sha384 = mk_hf "sha384" 128 sha384sum


(* AES *)

let aes_cbc_raw do_encrypt key iv input =
  begin
    match String.length key with
      | 16 | 24 | 32 -> ()
      | _ -> raise (Common.WrongParameter "key length should be 128, 192 or 256 bits")
  end;
  if String.length iv <> 16
  then raise (Common.WrongParameter "IV should be exactly 16 byte long");
  if (String.length input) mod 16 <> 0
  then raise (Common.WrongParameter "aes_cbc_raw expects already padded inputs");
  try
    aes_cbc do_encrypt key iv input
  with
    | Failure "context" -> raise (Common.UnexpectedError "Could not create AES context")
    | Failure "crypt" -> raise (Common.UnexpectedError "Internal error with AES")

let aes_cbc_raw_encrypt key iv input = aes_cbc_raw true key iv input
let aes_cbc_raw_decrypt key iv input = aes_cbc_raw false key iv input


let add_padding block_size input =
  let input_len = String.length input in
  let padding_len = block_size - ((input_len + 1) mod block_size) in
  input ^ (String.make (padding_len + 1) (char_of_int padding_len))

let drop_padding input =
  let input_len = String.length input in
  let padding_char = input.[input_len - 1] in
  let padding_len = int_of_char padding_char in
  let res = ref true in
  for i = 1 to padding_len do
    if input.[input_len - 1 -i] <> padding_char
    then res := false
  done;
  if !res
  then String.sub input 0 (input_len - padding_len - 1)
  else raise IncorrectPadding


let aes_cbc_encrypt key iv input =
  let padded_input = add_padding 16 input in
  aes_cbc_raw true key iv padded_input

let aes_cbc_decrypt key iv input =
  let res = aes_cbc_raw false key iv input in
  drop_padding res
