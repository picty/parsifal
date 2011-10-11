open Asn1Parser
open Asn1Parser.Asn1EngineParams
open Asn1Parser.Engine
open Asn1;;

try
  let pstate = pstate_of_channel (default_error_handling_function S_SpecFatallyViolated S_OK) "(stdin)" stdin in
  let opts = { type_repr = PrettyType; data_repr = PrettyData; resolver = None; indent_output = true } in
  while not (eos pstate) do
    let o = parse pstate in
    Printf.printf "%s" (string_of_object "" opts o)
  done
with
  | ParsingError (err, sev, pstate) ->
    print_endline ("Fatal (" ^ (string_of_severity sev) ^ "): " ^ 
		      (string_of_perror err) ^ (string_of_pstate pstate));;
