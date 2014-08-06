open OUnit
open TlsEnums
open TlsCrypto


let random_string len =
  let res = String.make len '\x00' in
  for i = 0 to (len - 1) do
    res.[i] <- char_of_int (Random.int 256)
  done;
  res

let aggregate exit_code = function
  | RSuccess _ -> exit_code
  | _ -> 1

let mk char len = String.make len char




let test_idempotence encrypt decrypt data =
  let encrypted_msg = encrypt data in
  match decrypt encrypted_msg with
  | false, _ -> failwith "test_idempotence: encryption/decryption is not idempotent"
  | true, data2 -> assert_equal data data2

let mk_idempotence_suite name encrypt decrypt n maxlen =
  let rec mk_one_test accu i curlen = match i, curlen with
    | 0, 0 -> accu
    | 0, _ -> mk_one_test accu n (curlen-1)
    | _, _ ->
      let t_name = name ^ "_idempotence_" ^ (string_of_int curlen) ^ "_" ^ (string_of_int i)
      and t_fun = fun () -> test_idempotence encrypt decrypt (random_string curlen) in
      mk_one_test ((t_name >:: t_fun)::accu) (i-1) curlen
  in
  mk_one_test [] n maxlen


let test_integrity encrypt decrypt data =
  let encrypted_msg = encrypt data in
  let len = String.length encrypted_msg in
  let pos = Random.int len in
  let delta = (Random.int 255) + 1 in
  encrypted_msg.[pos] <- char_of_int ((int_of_char encrypted_msg.[pos]) lxor delta);
  let integrity, _ =  decrypt encrypted_msg in
  assert_bool "integrity check should have failed" (not integrity)

let mk_check_integrity_check name encrypt decrypt n maxlen =
  let rec mk_one_test accu i curlen = match i, curlen with
    | 0, 0 -> accu
    | 0, _ -> mk_one_test accu n (curlen-1)
    | _, _ ->
      let t_name = name ^ "_integrity_check_" ^ (string_of_int curlen) ^ "_" ^ (string_of_int i)
      and t_fun = fun () -> test_integrity encrypt decrypt (random_string curlen) in
      mk_one_test ((t_name >:: t_fun)::accu) (i-1) curlen
  in
  mk_one_test [] n maxlen


(* TODO: add full key derivation, from PMS+CR+SR to encryption and decryption *)


(* TODO: Move these function to Tls module *)
let null_encrypt x = x
let null_decrypt x = true, x
(* TODO *)

let tests = List.flatten [
  mk_idempotence_suite "NULL_NULL" null_encrypt null_decrypt 3 17;
  mk_idempotence_suite "RC4_MD5" (rc4_encrypt hmac_md5 16 (mk 'k' 16) (mk 'K' 16))
    (rc4_decrypt hmac_md5 16 (mk 'k' 16) (mk 'K' 16)) 3 17;
  mk_idempotence_suite "RC4_SHA1" (rc4_encrypt hmac_sha1 20 (mk 'k' 20) (mk 'K' 16))
    (rc4_decrypt hmac_sha1 20 (mk 'k' 20) (mk 'K' 16)) 3 17;
  mk_idempotence_suite "AES128_MD5" (aes_cbc_implicit_encrypt hmac_md5 16 (mk 'k' 16) (mk 'I' 16) (mk 'K' 16))
    (aes_cbc_implicit_decrypt hmac_md5 16 (mk 'k' 16) (mk 'I' 16) (mk 'K' 16)) 3 17;
  mk_idempotence_suite "AES128_SHA1" (aes_cbc_implicit_encrypt hmac_sha1 20 (mk 'k' 20) (mk 'I' 16) (mk 'K' 16))
    (aes_cbc_implicit_decrypt hmac_sha1 20 (mk 'k' 20) (mk 'I' 16) (mk 'K' 16)) 3 17;
  mk_idempotence_suite "AES256_MD5" (aes_cbc_implicit_encrypt hmac_md5 16 (mk 'k' 16) (mk 'I' 16) (mk 'K' 32))
    (aes_cbc_implicit_decrypt hmac_md5 16 (mk 'k' 16) (mk 'I' 16) (mk 'K' 32)) 3 17;
  mk_idempotence_suite "AES256_SHA1" (aes_cbc_implicit_encrypt hmac_sha1 20 (mk 'k' 20) (mk 'I' 16) (mk 'K' 32))
    (aes_cbc_implicit_decrypt hmac_sha1 20 (mk 'k' 20) (mk 'I' 16) (mk 'K' 32)) 3 17;

  mk_check_integrity_check "RC4_MD5" (rc4_encrypt hmac_md5 16 (String.make 16 'A') (String.make 16 'B'))
    (rc4_decrypt hmac_md5 16 (String.make 16 'A') (String.make 16 'B')) 3 17;
  mk_check_integrity_check "RC4_SHA1" (rc4_encrypt hmac_sha1 20 (String.make 20 'A') (String.make 16 'B'))
    (rc4_decrypt hmac_sha1 20 (String.make 20 'A') (String.make 16 'B')) 3 17;
  mk_check_integrity_check "AES128_MD5" (aes_cbc_implicit_encrypt hmac_md5 16 (mk 'k' 16) (mk 'I' 16) (mk 'K' 16))
    (aes_cbc_implicit_decrypt hmac_md5 16 (mk 'k' 16) (mk 'I' 16) (mk 'K' 16)) 3 17;
  mk_check_integrity_check "AES128_SHA1" (aes_cbc_implicit_encrypt hmac_sha1 20 (mk 'k' 20) (mk 'I' 16) (mk 'K' 16))
    (aes_cbc_implicit_decrypt hmac_sha1 20 (mk 'k' 20) (mk 'I' 16) (mk 'K' 16)) 3 17;
  mk_check_integrity_check "AES256_MD5" (aes_cbc_implicit_encrypt hmac_md5 16 (mk 'k' 16) (mk 'I' 16) (mk 'K' 32))
    (aes_cbc_implicit_decrypt hmac_md5 16 (mk 'k' 16) (mk 'I' 16) (mk 'K' 32)) 3 17;
  mk_check_integrity_check "AES256_SHA1" (aes_cbc_implicit_encrypt hmac_sha1 20 (mk 'k' 20) (mk 'I' 16) (mk 'K' 32))
    (aes_cbc_implicit_decrypt hmac_sha1 20 (mk 'k' 20) (mk 'I' 16) (mk 'K' 32)) 3 17;
]

let suite = "Ciphersuites Unit Tests" >::: tests

let _ =
  Random.self_init ();
  let results = run_test_tt_main suite in
  exit (List.fold_left aggregate 0 results)
