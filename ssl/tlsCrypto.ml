open Cryptokit
open CryptoUtil
open TlsEnums

exception CryptoMayhem


let string_xor a b =
  let n_a = String.length a
  and n_b = String.length b in
  if n_a <> n_b then raise CryptoMayhem;
  let res = Bytes.of_string b in
  Cryptokit.xor_string a 0 res 0 n_a;
  Bytes.to_string res

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
let hmac_sha384 = hmac sha384sum 128
let hmac_sha512 = hmac sha512sum 128
let hmac_sha224 = hmac sha224sum 64


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
  | V_TLSv1_2, PRF_SHA384 ->  tls12_prf (hmac_sha384, 48)
  | V_TLSv1_2, PRF_Unknown ->  failwith "Not implemented: PRF hash function"
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
(* TODO: Use a more generic approach? *)
(* TODO: Rethink the interface to use MAC or ENC as parameters *)
(* TODO: Use a more generic return type for decryption (Encrypted/Decrypted) *)
(* TODO: Add a way to be laxist on mac errors (debug mode?) *)

let compute_mac mac_fun mac_key seq_num content_type version message =
  let maced_string = POutput.create () in
  BasePTypes.dump_uint64 maced_string seq_num;
  dump_tls_content_type maced_string content_type;
  dump_tls_version maced_string version;
  BasePTypes.dump_uint16 maced_string (String.length message);
  POutput.add_string maced_string message;
  mac_fun mac_key (POutput.contents maced_string)

let check_mac mac_fun mac_len mac_key seq_num content_type version plaintext =
  if String.length plaintext < mac_len
  then None
  else begin
    let real_len = (String.length plaintext) - mac_len in
    let real_plaintext = String.sub plaintext 0 real_len in
    let computed_mac = compute_mac mac_fun mac_key seq_num content_type version real_plaintext in
    let expected_mac = String.sub plaintext real_len mac_len in
    (* TODO: Constant time compare? *)
    (* TODO: For the moment, the implementation is really really from the 90's, timing leak-wise. *)
    if computed_mac = expected_mac
    then Some real_plaintext
    else None
  end

let rc4_decrypt mac_fun mac_len mac_key enc_key seq_num_ref  =
  let t = Cipher.arcfour enc_key Cipher.Decrypt in
  let f content_type version ciphertext =
    t#put_string ciphertext;
    let plaintext = t#get_string in
    match check_mac mac_fun mac_len mac_key !seq_num_ref content_type version plaintext with
    | Some p -> seq_num_ref := Int64.add !seq_num_ref 1L; true, p
    | None -> false, ciphertext
  in
  f

let rc4_encrypt mac_fun _mac_len mac_key enc_key seq_num_ref =
  let t = Cipher.arcfour enc_key Cipher.Encrypt in
  let f content_type version plaintext =
    let computed_mac = compute_mac mac_fun mac_key !seq_num_ref content_type version plaintext in
    seq_num_ref := Int64.add !seq_num_ref 1L;
    let plaintext_w_mac = plaintext ^ computed_mac in
    t#put_string plaintext_w_mac;
    t#get_string
  in
  f



class tls_length =
  object
    method pad buffer used =
      let n = Bytes.length buffer - used in
      assert (n > 0 && n < 256);
      (* TODO: This unsafe use is a hack due to the use of Cryptokit 1.10 *)
      (*       This is only needed when using this version of the library *)
      (*       and will be removed in the next version of Parsifal.       *)
      Bytes.fill buffer used n (Char.chr (n-1))
    method strip buffer =
      let blocksize = Bytes.length buffer in
      let n = Char.code (Bytes.get buffer (blocksize - 1)) in
      if n+1 > blocksize then raise (Cryptokit.Error Cryptokit.Bad_padding);
      (* Characters blocksize - n to blocksize - 1 must be equal to n *)
      for i = blocksize - n - 1 to blocksize - 2 do
        if Char.code (Bytes.get buffer i) <> n then raise (Cryptokit.Error Cryptokit.Bad_padding)
      done;
      blocksize - n - 1
  end

let tls_length = new tls_length


(* TODO: Add support for TLSv1.1 explicit IV *)

(* TODO: For the moment, the implementation is really really from the 90's, timing leak-wise. *)
let aes_cbc_implicit_decrypt mac_fun mac_len mac_key initial_iv key seq_num_ref =
  let iv_len = String.length initial_iv in
  let decrypt_aux iv ciphertext =
    let t = Cipher.aes ~mode:Cipher.CBC ~pad:tls_length ~iv:iv key Cryptokit.Cipher.Decrypt in
    transform_string t ciphertext
  in
  let current_decrypt = ref (decrypt_aux initial_iv) in
  let f content_type version ciphertext =
    let ciphertext_len = String.length ciphertext in
    if ciphertext_len < iv_len
    then false, ciphertext
    else begin
      try
        let plaintext = !current_decrypt ciphertext in
        let next_iv = String.sub ciphertext (ciphertext_len - iv_len) iv_len in
        current_decrypt := decrypt_aux next_iv;
        match check_mac mac_fun mac_len mac_key !seq_num_ref content_type version plaintext with
        | Some p -> seq_num_ref := Int64.add !seq_num_ref 1L; true, p
        | None -> false, ciphertext
      with _ -> false, ciphertext
    end
  in
  f

let aes_cbc_implicit_encrypt mac_fun _mac_len mac_key initial_iv key seq_num_ref =
  let iv_len = String.length initial_iv in
  let encrypt_aux iv ciphertext =
    let t = Cipher.aes ~mode:Cipher.CBC ~pad:tls_length ~iv:iv key Cryptokit.Cipher.Encrypt in
    transform_string t ciphertext
  in
  let current_encrypt = ref (encrypt_aux initial_iv) in
  let f content_type version plaintext =
    let computed_mac = compute_mac mac_fun mac_key !seq_num_ref content_type version plaintext in
    seq_num_ref := Int64.add !seq_num_ref 1L;
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
