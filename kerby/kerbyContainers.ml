open Parsifal
open Cryptokit
open BasePTypes
open Krb5

type 'a crypto_container = Encrypted of binstring | Decrypted of 'a

let value_of_crypto_container value_of_fun = function
  | Encrypted s -> VUnparsed (VString (s, true))
  | Decrypted x -> VAlias ("crypto_container", value_of_fun x)


(* UGLY AES *)
let byte_array_to_string = fun a -> let s = String.create (Array.length a) in
  Array.iteri (fun i x -> String.set s i x) a; s;;

let string_to_byte_array = fun s -> Array.init (String.length s) (fun i-> s.[i]);;

let aes_decrypt usage kvno ciphertext session_key =
  let aes_keyblock = {
    Krb5._mykrb5_keyblock_magic = -1760647421;
    Krb5._mykrb5_keyblock_enctype = 18;
    Krb5._mykrb5_keyblock_contents = string_to_byte_array session_key
  } in
  let enc_data = {
    Krb5._mykrb5_data_magic = 0 ;
    Krb5._mykrb5_data_data = string_to_byte_array ciphertext
  } in
  let enc_structure = {
    Krb5._mykrb5_enc_data_magic = -1760647418;
    Krb5._mykrb5_enc_data_enctype = 18;
    Krb5._mykrb5_enc_data_kvno = pop_opt 0 kvno;
    Krb5._mykrb5_enc_data_ciphertext = enc_data
  } in
  let (_, decrypted) = mL_krb5_c_decrypt aes_keyblock usage enc_structure in
  (byte_array_to_string decrypted.Krb5._mykrb5_data_data)

type 'a aes_container = 'a crypto_container

let parse_aes_container usage kvno aes_key name parse_fun input =
  let s = parse_rem_string input in
  match aes_key with
  | None -> Encrypted s
  | Some k ->
    let decrypted_s = aes_decrypt usage kvno s k in
    let new_input = get_in_container input name decrypted_s in
    let res = parse_fun new_input in
    check_empty_input true new_input;
    Decrypted res

let dump_aes_container _dump_fun _o = failwith "Pouet"

let value_of_aes_container = value_of_crypto_container


(* UGLY DES3 *)
let des3_decrypt ciphertext iv des3_key =
  let mydes_decrypt = Cryptokit.Cipher.triple_des ~mode:Cryptokit.Cipher.CBC ~pad:Cryptokit.Padding.length ~iv:iv (des3_key) Cryptokit.Cipher.Decrypt in
    transform_string mydes_decrypt ciphertext


type 'a des3_container = 'a crypto_container

let parse_des3_container opt_iv des3_key name parse_fun input =
  let s = parse_rem_string input in
  match opt_iv, des3_key with
  | Some (X509Basics.DES3Params iv), Some k ->
    let decrypted_s = des3_decrypt s iv k in
    let new_input = get_in_container input name decrypted_s in
    let res = parse_fun new_input in
    check_empty_input true new_input;
    Decrypted res
 | _ -> Encrypted s

let dump_des3_container _dump_fun _o = not_implemented "dump_des3_container"

let value_of_des3_container = value_of_crypto_container


