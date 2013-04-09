open Parsifal
open BasePTypes
open Random
open OUnit

open Lwt
open Lwt_io


(* Generic functions *)
(* TODO: Move those funs elsewhere *)

let random_string len () =
  let res = String.make len '\x00' in
  for i = 0 to (len - 1) do
    res.[i] <- char_of_int (Random.int 256)
  done;
  res

let ntimes n f () = for i = 1 to n do f (); done


let lwt_wrap parse_fun s =
  let inp, outp = pipe () in
  let t =
    write outp s >>= fun () ->
    input_of_channel "" inp >>=
    parse_fun >>= fun v ->
    close inp >>= fun () ->
    close outp >>= fun () ->
    return v
  in Lwt_unix.run t

let str_wrap parse_fun s = exact_parse parse_fun (input_of_string "" s)



(* Idempotence and string input tests *)
(* TODO: Move those funs elsewhere *)

let test_idem_pod parse dump rnd_fun () =
  let v1 = rnd_fun () in
  let v2 = parse (dump v1) in
  assert_equal v1 v2

let test_idem_dop parse dump rnd_fun () =
  let s1 = rnd_fun () in
  let s2 = dump (parse s1) in
  assert_equal s1 s2

let test_input_too_short parse expected_len _ =
  for l = 0 to expected_len - 1 do
    let input_name = (string_of_int l) ^ "-byte string" in
    let input = input_of_string input_name (random_string l ()) in
    assert_raises (ParsingException (OutOfBounds, [input_name, 0, Some l])) (fun _ -> exact_parse parse input)
  done

let test_input_too_long parse expected_len _ =
  let l = expected_len + 1 in
  let input_name = (string_of_int l) ^ "-byte string" in
  let input = input_of_string input_name (random_string l ()) in
  assert_raises (ParsingException (UnexpectedTrailingBytes, [input_name, expected_len, Some l])) (fun _ -> exact_parse parse input)



let test_int_type_string_of value_of rnd_fun () =
  let v = rnd_fun () in
  assert_equal (string_of_int v) (string_of_value (value_of v))

let test_int64_type_string_of value_of rnd_fun () =
  let v = rnd_fun () in
  assert_equal v (Int64.of_string ("0x" ^ (string_of_value (value_of v))))

let n = ref 100



let mk_int_tests name parse lwt_parse dump value_of expected_len =
  let max = if expected_len < 4 then 1 lsl (8 * expected_len) else 1000000000 in
  let rnd_fun () = Random.int max in
  let rnd_str = random_string expected_len in
  let prefix = "test_" ^ name in [
    (prefix ^ "_idem_pod") >:: ntimes !n (test_idem_pod (str_wrap parse) dump rnd_fun);
    (prefix ^ "_idem_dop") >:: ntimes !n (test_idem_dop (str_wrap parse) dump rnd_str);
    (prefix ^ "_idem_lpod") >:: ntimes !n (test_idem_pod (lwt_wrap lwt_parse) dump rnd_fun);
    (prefix ^ "_idem_dolp") >:: ntimes !n (test_idem_dop (lwt_wrap lwt_parse) dump rnd_str);
    (prefix ^ "_string_of") >:: test_int_type_string_of value_of rnd_fun;
    (prefix ^ "_input_too_short") >:: test_input_too_short parse expected_len;
    (prefix ^ "_input_too_long") >:: test_input_too_long parse expected_len;
  ]

let mk_int64_tests name parse lwt_parse dump value_of =
  let rnd_fun () = Random.int64 (Int64.max_int) in
  let rnd_str = random_string 8 in
  let prefix = "test_" ^ name in [
    (prefix ^ "_idem_pod") >:: ntimes !n (test_idem_pod (str_wrap parse) dump rnd_fun);
    (prefix ^ "_idem_dop") >:: ntimes !n (test_idem_dop (str_wrap parse) dump rnd_str);
    (prefix ^ "_idem_lpod") >:: ntimes !n (test_idem_pod (lwt_wrap lwt_parse) dump rnd_fun);
    (prefix ^ "_idem_dolp") >:: ntimes !n (test_idem_dop (lwt_wrap lwt_parse) dump rnd_str);
    (prefix ^ "_string_of") >:: test_int64_type_string_of value_of rnd_fun;
    (prefix ^ "_input_too_short") >:: test_input_too_short parse 8;
    (prefix ^ "_input_too_long") >:: test_input_too_long parse 8;
  ]




(* TODO: Use modules when they exists? *)
let int_tests =
  (mk_int_tests "uint8" parse_uint8 lwt_parse_uint8 dump_uint8 value_of_uint8 1)@
    (mk_int_tests "uint16" parse_uint16 lwt_parse_uint16 dump_uint16 value_of_uint16 2)@
    (mk_int_tests "uint16le" parse_uint16le lwt_parse_uint16le dump_uint16le value_of_uint16le 2)@
    (mk_int_tests "uint24" parse_uint24 lwt_parse_uint24 dump_uint24 value_of_uint24 3)@
    (mk_int_tests "uint32" parse_uint32 lwt_parse_uint32 dump_uint32 value_of_uint32 4)@
    (mk_int_tests "uint32le" parse_uint32le lwt_parse_uint32le dump_uint32le value_of_uint32le 4)@
    (mk_int64_tests "uint64" parse_uint64 lwt_parse_uint64 dump_uint64 value_of_uint64)@
    (mk_int64_tests "uint64le" parse_uint64le lwt_parse_uint64le dump_uint64le value_of_uint64le)


let string_tests = [ (* TODO: string tests (ok/nok), drop_bytes *) ]
let list_tests = [ (* TODO: tests, including parsingStop *) ]
let container_tests = [ (* TODO *) ]
let array_tests = [ (* TODO *) ]
let hash_tests = [ (* TODO, when it is implemented... *) ]

let tests = List.flatten [
  int_tests; string_tests;
  list_tests; container_tests; array_tests; hash_tests
]

let suite = "Base PTypes Unit Tests" >::: tests

let _ =
  Random.self_init ();
  run_test_tt_main suite
