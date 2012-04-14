open Common
open Types
open ParsingEngine
open Ssl2

let _ =
  let pstate = pstate_of_channel "(stdin)" stdin in

  Ssl2.parse_certificates := false;
  tolerance := s_specfatallyviolated;
  minDisplay := s_specfatallyviolated;
  
  try
    while not (eos pstate) do
      let msg = Ssl2.parse pstate in
      match msg with
	| ClientHello (proto, cs, _sid, _challenge) ->
	  Printf.printf "ClientHello\n";
	  Printf.printf "  Protocol version: %s\n" (TlsCommon.protocol_version_string_of_int proto);
	  Printf.printf "  Ciphersuites:\n    %s\n" (String.concat "\n    " (List.map (hexdump_int_n 6) cs));
	| UnknownMsg s ->
	  Printf.printf "Unknown...\n"
    done
  with
    | OutOfBounds s ->
      output_string stderr ("Out of bounds (" ^ s ^ ")\n")
    | ParsingError (err, sev, pstate) ->
      output_string stderr ((string_of_parsing_error "Parsing error" err sev pstate) ^ "\n");;
