open ParsingEngine
open Asn1

let _ =
  try
    let s = "\x30\x08\x01\x01\xff\x05\x00\x02\x01\x00" in
    let pstate = pstate_of_string None s in

    let (c, isC, t) = extract_header pstate in
    let new_pstate = extract_length pstate (string_of_header_pretty c isC t) in
    let remaining = pop_string new_pstate in
    Printf.printf "%s (%s) len=%d : %s \n" (string_of_header_pretty c isC t)
      (string_of_header_raw c isC t) (String.length remaining) (Common.hexdump remaining);

    let o = exact_parse None s in
    let opts = { type_repr = PrettyType; data_repr = PrettyData; indent_output = true } in
    Printf.printf "%s" (string_of_object "" opts o)
  with
    | OutOfBounds s ->
      output_string stderr ("Out of bounds in " ^ s ^ ")")
    | ParsingError (err, sev, pstate) ->
      output_string stderr (string_of_parsing_error "Fatal" err sev pstate);;

