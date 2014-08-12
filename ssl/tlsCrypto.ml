open Cryptokit
open CryptoUtil
open TlsEnums

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



let choose_prf version prf_hash = match version, prf_hash with
  | V_SSLv2, _ -> failwith "Not implemented: SSLv2 PRF"
  | V_SSLv3, _ -> failwith "Not implemented: SSLv3 PRF"
  | (V_TLSv1 | V_TLSv1_1), _ -> tls1_prf
  | V_TLSv1_2, (PRF_Default | PRF_SHA256) ->  tls12_prf (hmac_sha256, 32)
  | V_TLSv1_2, (PRF_SHA384 | PRF_Unknown) ->  failwith "Not implemented: PRF hash function"
  | V_Unknown _, _ -> failwith "Not implemented: PRF choice using an unknown version"



(* PRF and PMS/MS/KB generation *)

let mk_master_secret prf (cr, sr) = function
  | (Tls.NoKnownSecret | Tls.MasterSecret _) as secret -> secret
  | Tls.PreMasterSecret pms -> Tls.MasterSecret (prf pms "master secret" (cr ^ sr) 48)


let mk_key_block prf ms (cr, sr) block_lens =
  let rec split_block block cur len lens =
    match lens, len - cur with
    | [], 0 -> []
    | [], _ -> failwith "Internal mk_key_block unexpected error"
    | l::ls, rem ->
      if rem < l then failwith "Internal mk_key_block unexpected error";
      (String.sub block cur l)::(split_block block (cur+l) len ls)
  in
  let total_len = List.fold_left (+) 0 block_lens in
  let key_block = prf ms "key expansion" (sr ^ cr) total_len in
  if String.length key_block <> total_len
  then failwith "Internal mk_key_block unexpected error";
  split_block key_block 0 total_len block_lens



(* Encryption / Decryption methods *)

let check_mac mac_fun mac_len mac_key plaintext =
  if String.length plaintext < mac_len
  then None
  else begin
    let real_len = (String.length plaintext) - mac_len in
    let real_plaintext = String.sub plaintext 0 real_len in
    let computed_mac = mac_fun mac_key real_plaintext in
    let expected_mac = String.sub plaintext real_len mac_len in
    (* TODO: Constant time compare? *)
    (* TODO: For the moment, the implementation is really really from the 90's, timing leak-wise. *)
    if computed_mac = expected_mac
    then Some real_plaintext
    (* TODO: Add a way to be laxist on mac errors (debug mode?) *)
    else None
  end

let rc4_decrypt mac_fun mac_len mac_key enc_key =
  let t = Cipher.arcfour enc_key Cipher.Decrypt in
  let f ciphertext =
    t#put_string ciphertext;
    let plaintext = t#get_string in
    (* TODO: Use a more generic type (Encrypted/Decrypted) *)
    match check_mac mac_fun mac_len mac_key plaintext with
    | Some p -> true, p
    | None -> false, ciphertext
  in
  f

let rc4_encrypt mac_fun _mac_len mac_key enc_key =
  let t = Cipher.arcfour enc_key Cipher.Encrypt in
  let f plaintext =
    let computed_mac = mac_fun mac_key plaintext in
    let plaintext_w_mac = plaintext ^ computed_mac in
    t#put_string plaintext_w_mac;
    t#get_string
  in
  f



class tls_length =
  object
    method pad buffer used =
      let n = String.length buffer - used in
      assert (n > 0 && n < 256);
      String.fill buffer used n (Char.chr (n-1))
    method strip buffer =
      let blocksize = String.length buffer in
      let n = Char.code buffer.[blocksize - 1] in
      if n+1 > blocksize then raise (Cryptokit.Error Cryptokit.Bad_padding);
      (* Characters blocksize - n to blocksize - 1 must be equal to n *)
      for i = blocksize - n - 1 to blocksize - 2 do
        if Char.code buffer.[i] <> n then raise (Cryptokit.Error Cryptokit.Bad_padding)
      done;
      blocksize - n - 1
  end

let tls_length = new tls_length


(* TODO: Rethink the interface to use MAC or ENC as parameters *)
(* TODO: Add support for TLSv1.1 explicit IV *)

(* TODO: For the moment, the implementation is really really from the 90's, timing leak-wise. *)
let aes_cbc_implicit_decrypt mac_fun mac_len mac_key initial_iv key =
  let iv_len = String.length initial_iv in
  let decrypt_aux iv ciphertext =
    let t = Cipher.aes ~mode:Cipher.CBC ~pad:tls_length ~iv:iv key Cryptokit.Cipher.Decrypt in
    transform_string t ciphertext
  in
  let current_decrypt = ref (decrypt_aux initial_iv) in
  let f ciphertext =
    let ciphertext_len = String.length ciphertext in
    if ciphertext_len < iv_len
    then false, ciphertext
    else begin
      try
	let plaintext = !current_decrypt ciphertext in
	let next_iv = String.sub ciphertext (ciphertext_len - iv_len) iv_len in
	current_decrypt := decrypt_aux next_iv;
	(* TODO: Use a more generic type (Encrypted/Decrypted) *)
	match check_mac mac_fun mac_len mac_key plaintext with
	| Some p -> true, p
	| None -> false, ciphertext
      with _ -> false, ciphertext
    end
  in
  f

let aes_cbc_implicit_encrypt mac_fun _mac_len mac_key initial_iv key =
  let iv_len = String.length initial_iv in
  let encrypt_aux iv ciphertext =
    let t = Cipher.aes ~mode:Cipher.CBC ~pad:tls_length ~iv:iv key Cryptokit.Cipher.Encrypt in
    transform_string t ciphertext
  in
  let current_encrypt = ref (encrypt_aux initial_iv) in
  let f plaintext =
    let computed_mac = mac_fun mac_key plaintext in
    let plaintext_w_mac = plaintext ^ computed_mac in
    let ciphertext = !current_encrypt plaintext_w_mac in
    let ciphertext_len = String.length ciphertext in
    if ciphertext_len < iv_len
    then failwith "aes_cbc_implicit_encrypt: invalid encryption result"
    else begin
      let next_iv = String.sub ciphertext (ciphertext_len - iv_len) iv_len in
      current_encrypt := encrypt_aux next_iv;
      ciphertext
    end
  in
  f
