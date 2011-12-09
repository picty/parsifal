open ParsingEngine
open X509

let _ =
  try
    let pstate = pstate_of_channel "(stdin)" stdin in
    let cert = X509.parse pstate in
    Printf.printf "%s" (String.concat "\n" (X509.to_string cert))
  with
    | OutOfBounds s -> output_string stderr ("Out of bounds in " ^ s ^ ")")
    | ParsingError (err, sev, pstate) -> output_string stderr (string_of_parsing_error "Fatal" err sev pstate);;

