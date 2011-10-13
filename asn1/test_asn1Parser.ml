open Asn1;;
open Asn1.Asn1EngineParams;;
open Asn1.Engine;;

try
  let s = "\x30\x08\x01\x01\xff\x05\x00\x02\x01\x00" in
  let pstate = pstate_of_string (default_error_handling_function S_SpecFatallyViolated S_OK) "Test" s in

  let (c, isC, t) = extract_header pstate in
  extract_length pstate (string_of_header_pretty c isC t);
  let remaining = pop_string pstate in
  Printf.printf "%s (%s) len=%d : %s \n" (string_of_header_pretty c isC t)
    (string_of_header_raw c isC t) (String.length remaining) (Common.hexdump remaining);

  let o = exact_parse (default_error_handling_function S_SpecFatallyViolated S_OK) "Test" s in
  let opts = { type_repr = PrettyType; data_repr = PrettyData; resolver = None; indent_output = true } in
  Printf.printf "%s" (string_of_object "" opts o)
with
  | ParsingError (err, sev, pstate) ->
    print_endline ("Fatal (" ^ (string_of_severity sev) ^ "): " ^ 
		      (string_of_perror err) ^ (string_of_pstate pstate));;

