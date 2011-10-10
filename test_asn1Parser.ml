open Asn1Parser
open Asn1Parser.Asn1EngineParams
open Asn1Parser.Engine
open Asn1

let s = "\x02\x01\x00"

let pstate = make_pstate (default_error_handling_function S_SpecFatallyViolated S_OK) "Test" s

let (c, isC, t), pstate = extract_header pstate;; 
let pstate = extract_length pstate;;

Printf.printf "%s (%s) len=%d : %s \n" (string_of_header_pretty c isC t) (string_of_header_raw c isC t) pstate.len (hexdump (String.sub pstate.str pstate.offset pstate.len))
