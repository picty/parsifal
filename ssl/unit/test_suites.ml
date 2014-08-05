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


(* TODO:
   - add negative checks (ciphertext alteration should lead to fails)
   - add full key derivation, from PMS+CR+SR to encryption and decryption *)


(* TODO: Move these function to Tls module *)
let null_encrypt x = x
let null_decrypt x = true, x
(* TODO *)

let tests = List.flatten [
  mk_idempotence_suite "NULL_NULL" null_encrypt null_decrypt 10 20;
]

let suite = "Ciphersuites Unit Tests" >::: tests

let _ =
  Random.self_init ();
  let results = run_test_tt_main suite in
  exit (List.fold_left aggregate 0 results)
