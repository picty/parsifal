open OUnit
open Random
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
  (* TODO: Choose the position and the new value using Random *)
  let len = String.length encrypted_msg in
  if encrypted_msg.[len / 2] = '\x00'
  then encrypted_msg.[len / 2] <- 'A'
  else encrypted_msg.[len / 2] <- '\x00';
  (* TODO *)
  let integrity, _ =  decrypt encrypted_msg in
  assert_bool "integrity check should have failed" (not integrity)

let mk_check_integrity_check name encrypt decrypt _n maxlen =
  let rec mk_one_test accu i curlen = match i, curlen with
    | 0, 0 -> accu
    | 0, _ -> mk_one_test accu 1 (* TODO: n *) (curlen-1)
    | _, _ ->
      let t_name = name ^ "_integrity_check_" ^ (string_of_int curlen) ^ "_" ^ (string_of_int i)
      and t_fun = fun () -> test_integrity encrypt decrypt (random_string curlen) in
      mk_one_test ((t_name >:: t_fun)::accu) (i-1) curlen
  in
  (* TODO: When test_integrity is randomised, make n a variable *)
  mk_one_test [] 1 (* TODO: n *) maxlen


(* TODO:
   - add full key derivation, from PMS+CR+SR to encryption and decryption *)


(* TODO: Move these function to Tls module *)
let null_encrypt x = x
let null_decrypt x = true, x
(* TODO *)

let tests = List.flatten [
  mk_idempotence_suite "NULL_NULL" null_encrypt null_decrypt 10 20;
  mk_idempotence_suite "RC4_MD5" (rc4_encrypt hmac_md5 16 (String.make 16 'A') (String.make 16 'B'))
    (rc4_decrypt hmac_md5 16 (String.make 16 'A') (String.make 16 'B')) 10 20;
  mk_idempotence_suite "RC4_SHA1" (rc4_encrypt hmac_sha1 20 (String.make 20 'A') (String.make 16 'B'))
    (rc4_decrypt hmac_sha1 20 (String.make 20 'A') (String.make 16 'B')) 10 20;

  mk_check_integrity_check "RC4_MD5" (rc4_encrypt hmac_md5 16 (String.make 16 'A') (String.make 16 'B'))
    (rc4_decrypt hmac_md5 16 (String.make 16 'A') (String.make 16 'B')) 10 20;
  mk_check_integrity_check "RC4_SHA1" (rc4_encrypt hmac_sha1 20 (String.make 20 'A') (String.make 16 'B'))
    (rc4_decrypt hmac_sha1 20 (String.make 20 'A') (String.make 16 'B')) 10 20;
]

let suite = "Ciphersuites Unit Tests" >::: tests

let _ =
  Random.self_init ();
  let results = run_test_tt_main suite in
  exit (List.fold_left aggregate 0 results)
