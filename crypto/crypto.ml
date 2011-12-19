(* C functions *)

external md5sum : string -> string = "md5sum"
external sha1sum : string -> string = "sha1sum"
external sha224_256sum : string -> bool -> string = "sha224_256sum"
external sha384_512sum : string -> bool -> string = "sha384_512sum"
external aes_cbc : bool -> string -> string -> string -> string = "aes_cbc"

external exp_mod : string -> string -> string -> string = "exp_mod"


(* Exception for the crypto code *)
exception IncorrectPadding
exception WrongParameters of string


let sha224sum s = sha224_256sum s true
let sha256sum s = sha224_256sum s false
let sha384sum s = sha384_512sum s true
let sha512sum s = sha384_512sum s false
(* AES *)

let aes_cbc_raw do_encrypt key iv input =
  begin
    match String.length key with
      | 16 | 24 | 32 -> ()
      | _ -> raise (WrongParameters "key length should be 128, 192 or 256 bits")
  end;
  if String.length iv <> 16
  then raise (WrongParameters "IV should be exactly 16 byte long");
  if (String.length input) mod 16 <> 0
  then raise (WrongParameters "aes_cbc_raw expects already padded inputs");
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
