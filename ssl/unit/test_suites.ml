open OUnit
open Parsifal
open Tls
open TlsEnums
open TlsCrypto


let random_string len =
  let res = Bytes.make len '\x00' in
  for i = 0 to (len - 1) do
    Bytes.set res i (char_of_int (Random.int 256))
  done;
  Bytes.to_string res (* TODO: Use unsafe_to_string *)

let aggregate exit_code = function
  | RSuccess _ -> exit_code
  | _ -> 1

let mk char len = String.make len char




let test_idempotence encrypt decrypt data =
  let encrypted_msg = encrypt CT_ApplicationData V_TLSv1 data in
  match decrypt CT_ApplicationData V_TLSv1 encrypted_msg with
  | false, _ -> failwith "test_idempotence: encryption/decryption is not idempotent"
  | true, data2 -> assert_equal data data2

let mk_idempotence_suite name encrypt decrypt n maxlen =
  let rec mk_one_test accu i curlen = match i, curlen with
    | 0, 0 -> accu
    | 0, _ -> mk_one_test accu n (curlen-1)
    | _, _ ->
      let t_name = name ^ "_idempotence_" ^ (string_of_int curlen) ^ "_" ^ (string_of_int i) in
      let t_fun () = test_idempotence encrypt decrypt (random_string curlen) in
      mk_one_test ((t_name >:: t_fun)::accu) (i-1) curlen
  in
  mk_one_test [] n maxlen


let test_integrity encrypt decrypt data =
  let encrypted_msg = Bytes.of_string (encrypt CT_ApplicationData V_TLSv1 data) in
  let len = Bytes.length encrypted_msg in
  let pos = Random.int len in
  let delta = (Random.int 255) + 1 in
  Bytes.set encrypted_msg pos (char_of_int ((int_of_char (Bytes.get encrypted_msg pos)) lxor delta));
  let integrity, _ =  decrypt CT_ApplicationData V_TLSv1 (Bytes.to_string encrypted_msg) in
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


let tests = List.flatten [
  mk_idempotence_suite "NULL_NULL" (null_encrypt ClientToServer) (null_decrypt ClientToServer) 3 17;
  mk_idempotence_suite "RC4_MD5" (rc4_encrypt hmac_md5 16 (mk 'k' 16) (mk 'K' 16) (ref 0L))
    (rc4_decrypt hmac_md5 16 (mk 'k' 16) (mk 'K' 16) (ref 0L)) 3 17;
  mk_idempotence_suite "RC4_SHA1" (rc4_encrypt hmac_sha1 20 (mk 'k' 20) (mk 'K' 16) (ref 0L))
    (rc4_decrypt hmac_sha1 20 (mk 'k' 20) (mk 'K' 16) (ref 0L)) 3 17;
  mk_idempotence_suite "AES128_MD5" (aes_cbc_implicit_encrypt hmac_md5 16 (mk 'k' 16) (mk 'I' 16) (mk 'K' 16) (ref 0L))
    (aes_cbc_implicit_decrypt hmac_md5 16 (mk 'k' 16) (mk 'I' 16) (mk 'K' 16) (ref 0L)) 3 17;
  mk_idempotence_suite "AES128_SHA1" (aes_cbc_implicit_encrypt hmac_sha1 20 (mk 'k' 20) (mk 'I' 16) (mk 'K' 16) (ref 0L))
    (aes_cbc_implicit_decrypt hmac_sha1 20 (mk 'k' 20) (mk 'I' 16) (mk 'K' 16) (ref 0L)) 3 17;
  mk_idempotence_suite "AES256_MD5" (aes_cbc_implicit_encrypt hmac_md5 16 (mk 'k' 16) (mk 'I' 16) (mk 'K' 32) (ref 0L))
    (aes_cbc_implicit_decrypt hmac_md5 16 (mk 'k' 16) (mk 'I' 16) (mk 'K' 32) (ref 0L)) 3 17;
  mk_idempotence_suite "AES256_SHA1" (aes_cbc_implicit_encrypt hmac_sha1 20 (mk 'k' 20) (mk 'I' 16) (mk 'K' 32) (ref 0L))
    (aes_cbc_implicit_decrypt hmac_sha1 20 (mk 'k' 20) (mk 'I' 16) (mk 'K' 32) (ref 0L)) 3 17;

  mk_check_integrity_check "RC4_MD5" (rc4_encrypt hmac_md5 16 (String.make 16 'A') (String.make 16 'B') (ref 0L))
    (rc4_decrypt hmac_md5 16 (String.make 16 'A') (String.make 16 'B') (ref 0L)) 3 17;
  mk_check_integrity_check "RC4_SHA1" (rc4_encrypt hmac_sha1 20 (String.make 20 'A') (String.make 16 'B') (ref 0L))
    (rc4_decrypt hmac_sha1 20 (String.make 20 'A') (String.make 16 'B') (ref 0L)) 3 17;
  mk_check_integrity_check "AES128_MD5" (aes_cbc_implicit_encrypt hmac_md5 16 (mk 'k' 16) (mk 'I' 16) (mk 'K' 16) (ref 0L))
    (aes_cbc_implicit_decrypt hmac_md5 16 (mk 'k' 16) (mk 'I' 16) (mk 'K' 16) (ref 0L)) 3 17;
  mk_check_integrity_check "AES128_SHA1" (aes_cbc_implicit_encrypt hmac_sha1 20 (mk 'k' 20) (mk 'I' 16) (mk 'K' 16) (ref 0L))
    (aes_cbc_implicit_decrypt hmac_sha1 20 (mk 'k' 20) (mk 'I' 16) (mk 'K' 16) (ref 0L)) 3 17;
  mk_check_integrity_check "AES256_MD5" (aes_cbc_implicit_encrypt hmac_md5 16 (mk 'k' 16) (mk 'I' 16) (mk 'K' 32) (ref 0L))
    (aes_cbc_implicit_decrypt hmac_md5 16 (mk 'k' 16) (mk 'I' 16) (mk 'K' 32) (ref 0L)) 3 17;
  mk_check_integrity_check "AES256_SHA1" (aes_cbc_implicit_encrypt hmac_sha1 20 (mk 'k' 20) (mk 'I' 16) (mk 'K' 32) (ref 0L))
    (aes_cbc_implicit_decrypt hmac_sha1 20 (mk 'k' 20) (mk 'I' 16) (mk 'K' 32) (ref 0L)) 3 17;
]

let suite = "Ciphersuites Unit Tests" >::: tests

let _ =
  Random.self_init ();
  let results = run_test_tt_main suite in
  exit (List.fold_left aggregate 0 results)
