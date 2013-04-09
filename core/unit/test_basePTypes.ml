open Parsifal
open BasePTypes
open OUnit

let test_int_type_idem_pod parse dump v1 _ =
  let real_parse = exact_parse parse in
  let v2 = real_parse (input_of_string "dump(v1)" (dump v1)) in
  assert_equal v1 v2

let test_int_type_idem_dop parse dump s1 _ =
  let real_parse = exact_parse parse in
  let s2 = dump (real_parse (input_of_string "s1" s1)) in
  assert_equal s1 s2

let test_int_type_string_of value_of v1 _ =
  assert_equal (string_of_int v1) (string_of_value (value_of v1))

let test_int64_type_string_of value_of v1 _ =
  assert_equal v1 (Int64.of_string ("0x" ^ (string_of_value (value_of v1))))

let test_int_type_empty_input parse _ =
  let real_parse = exact_parse parse in
  assert_raises (ParsingException (OutOfBounds, ["empty string", 0, Some 0])) (fun _ -> real_parse (input_of_string "empty string" ""))


let mk_int_tests name parse dump value_of v1 s1 =
  (* TODO: Add lwt tests *)
  (* TODO: Add test_*int_nok *)
  let prefix = "test_" ^ name in [
    (prefix ^ "_idem_pod") >:: test_int_type_idem_pod parse dump v1;
    (prefix ^ "_idem_dop") >:: test_int_type_idem_dop parse dump s1;
    (prefix ^ "_string_of") >:: test_int_type_string_of value_of v1;
    (prefix ^ "_empty_input") >:: test_int_type_empty_input parse;
  ]

let mk_int64_tests name parse dump value_of v1 s1 =
  (* TODO: Add lwt tests *)
  (* TODO: Add test_*int_nok *)
  let prefix = "test_" ^ name in [
    (prefix ^ "_idem_pod") >:: test_int_type_idem_pod parse dump v1;
    (prefix ^ "_idem_dop") >:: test_int_type_idem_dop parse dump s1;
    (prefix ^ "_string_of") >:: test_int64_type_string_of value_of v1;
    (prefix ^ "_empty_input") >:: test_int_type_empty_input parse;
  ]


(* TODO: Add random stuff? *)
(* TODO: Use modules when they exists? *)
let int_tests =
  (mk_int_tests "uint8" parse_uint8 dump_uint8 value_of_uint8 14 "\x34")@
    (mk_int_tests "uint16" parse_uint16 dump_uint16 value_of_uint16 65520 "\x0d\x2a")@
    (mk_int_tests "uint16le" parse_uint16le dump_uint16le value_of_uint16le 65520 "\x0d\x2a")@
    (mk_int_tests "uint24" parse_uint24 dump_uint24 value_of_uint24 582749 "ABC")@
    (mk_int_tests "uint32" parse_uint32 dump_uint32 value_of_uint32 2000000000 "\xff\x12\x43\x10")@
    (mk_int_tests "uint32le" parse_uint32le dump_uint32le value_of_uint32le 2000000000 "\xff\x12\x43\x10")@
    (mk_int64_tests "uint64" parse_uint64 dump_uint64 value_of_uint64 (Int64.of_string "123456789012") "ABCDEFGH")@
    (mk_int64_tests "uint64le" parse_uint64le dump_uint64le value_of_uint64le (Int64.of_string "123456789012") "ABCDEFGH")


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
  run_test_tt_main suite
