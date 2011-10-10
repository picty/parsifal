open Asn1Parser
open Asn1Parser.Asn1EngineParams
open Asn1Parser.Engine
open Asn1;;

try
  let s = "\x30\x08\x01\x01\xff\x05\x00\x02\x01\x00" in
  let pstate = make_pstate (default_error_handling_function S_SpecFatallyViolated S_OK) "Test" s in

  let (c, isC, t), pstate = extract_header pstate in
  let pstate, _ = extract_length pstate in

  Printf.printf "%s (%s) len=%d : %s \n" (string_of_header_pretty c isC t)
    (string_of_header_raw c isC t) pstate.len (hexdump (String.sub pstate.str pstate.offset pstate.len));

  let o = exact_parse (default_error_handling_function S_SpecFatallyViolated S_OK) "Test" s in
  let opts = { type_repr = PrettyType; data_repr = PrettyData; resolver = None; indent_output = true } in
  Printf.printf "%s" (string_of_object "" opts o)
with
  | ParsingError (err, sev, pstate) ->
    print_endline ("Fatal (" ^ (string_of_severity sev) ^ "): " ^ 
		      (string_of_perror err) ^ (string_of_pstate pstate));;

