open OUnit

open Parsifal
open BasePTypes
open Base64


(* Generic functions *)
(* TODO: Move those funs elsewhere *)

let random_string len () =
  let res = String.make len '\x00' in
  for i = 0 to (len - 1) do
    res.[i] <- char_of_int (Random.int 256)
  done;
  res

let ntimes n f () = for _i = 1 to n do f (); done


let str_wrap parse_fun s = exact_parse parse_fun (input_of_string "" s)



(* Idempotence and string input tests *)
(* TODO: Move those funs elsewhere *)

let test_idem_pod parse dump rnd_fun () =
  let v1 = rnd_fun () in
  let v2 = parse (exact_dump dump v1) in
  assert_equal v1 v2


(* TODO: Add tests on invalid headers, and tests on invalid base64 chars *)


let n = ref 10

let mk_one_b64_test header_type len =
  let prefix, dump_hdr = match header_type with
    | AnyHeader -> "test_anyheader", HeaderInList ["ANYHEADER"]
    | HeaderInList [_] -> "test_header", header_type
    | HeaderInList _ | NoHeader -> "test_noheader", header_type
  in
  let rnd_str = random_string len in
  let parse = parse_base64_container header_type "base64_container" parse_rem_string
  and dump = dump_base64_container dump_hdr dump_string in
  [(prefix ^ "_idem_pod_" ^ (string_of_int len)) >:: ntimes !n (test_idem_pod (str_wrap parse) dump rnd_str)]


let base64_tests =
  let headers = [AnyHeader; HeaderInList ["SOMETHING"]; NoHeader]
  and lens = [0; 1; 2; 3; 4; 5; 6; 7; 14; 15; 16; 17; 47; 48; 49; 1024; 1025; 1026] in
  List.flatten (List.flatten (List.map (fun h -> List.map (fun l -> mk_one_b64_test h l) lens) headers))


let tests = List.flatten [
  base64_tests
]

let suite = "Base64 Unit Tests" >::: tests

let aggregate exit_code = function
  | RSuccess _ -> exit_code
  | _ -> 1

let _ =
  Random.self_init ();
  let results = run_test_tt_main suite in
  exit (List.fold_left aggregate 0 results)
