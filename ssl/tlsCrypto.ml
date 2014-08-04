open Cryptokit
open CryptoUtil

exception CryptoMayhem


let string_xor a b =
  let n_a = String.length a
  and n_b = String.length b in
  if n_a <> n_b then raise CryptoMayhem;
  let res = String.copy b in
  Cryptokit.xor_string a 0 res 0 n_a;
  res

(* TODO: Move this elsewhere? Reuse Cryptokit? *)
let hmac hash_fun block_len k m =
  let k_len = String.length k in
  (* TODO: Do better? *)
  if k_len > block_len then raise CryptoMayhem;

  let in_buf = Buffer.create block_len
  and out_buf = Buffer.create block_len in
  let rec mk_real_keys i =
    if i = block_len
    then Buffer.contents in_buf, Buffer.contents out_buf
    else begin
      let next_key_char = if i < k_len then int_of_char k.[i] else 0 in
      Buffer.add_char in_buf (char_of_int (next_key_char lxor 0x36));
      Buffer.add_char out_buf (char_of_int (next_key_char lxor 0x5c));
      mk_real_keys (i+1)
    end
  in

  let in_key, out_key = mk_real_keys 0 in
  hash_fun (out_key ^ (hash_fun (in_key ^ m)))


let hmac_md5 = hmac md5sum 64
let hmac_sha1 = hmac sha1sum 64
let hmac_sha256 = hmac sha256sum 64


let tls_P_hash hmac_fun hash_len secret seed len =
  let res = Buffer.create len in
  let n_blocks = (len + (hash_len - 1)) / hash_len in

  let rec mk_next_block a_i i =
    if i = n_blocks
    then Buffer.sub res 0 len
    else begin
      let a_i_plus_1 = hmac_fun secret a_i in
      let next_block = hmac_fun secret (a_i_plus_1 ^ seed) in
      Buffer.add_string res next_block;
      mk_next_block a_i_plus_1 (i+1)
    end
  in

  mk_next_block seed 0



let tls1_prf secret label seed len =
  let l = String.length secret in
  let l' = (l + 1) / 2 in
  let s1 = String.sub secret 0 l'
  and s2 = String.sub secret (l - l') l' in

  let md5_part = tls_P_hash hmac_md5 16 s1 (label ^ seed) len
  and sha1_part = tls_P_hash hmac_sha1 20 s2 (label ^ seed) len in
  string_xor md5_part sha1_part



let tls12_prf (hmac_fun, hlen) secret label seed len =
  tls_P_hash hmac_fun hlen secret (label ^ seed) len

