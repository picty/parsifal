open RandomEngine
open Getopt
open CryptoUtil

let state = make_bh_prng sha256sum "tititoto"

let reseed_urandom () =
  let seed = String.make 1024 ' ' in
  let f = open_in "/dev/urandom" in
  really_input f seed 0 1024;
  state.seed seed

let reseed s = state.seed s; ActionDone
let print_random_int n = print_endline (string_of_int (random_int state n)); ActionDone
let print_random_string n = print_endline (Parsifal.hexdump (random_string state n)); ActionDone

let options = [
  mkopt (Some 'h') "help" Usage "show this help";

  mkopt (Some 'u') "urandom" (TrivialFun reseed_urandom) "seed the generator with 1024 bytes from /dev/urandom";
  mkopt (Some 's') "seed" (StringFun reseed) "seed the generator with s";
  mkopt (Some 'I') "integer" (IntFun print_random_int) "print a random int between 0 and n";
  mkopt (Some 'S') "string" (IntFun print_random_string) "print a random string of n characters";
]


let _ =
  ignore (parse_args ~progname:"test_random" options Sys.argv);
