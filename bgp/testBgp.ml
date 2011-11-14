(* Guillaume Valadon <guillaume.valadon@ssi.gouv.fr> *)
(* Olivier Levillain <olivier.levillain@ssi.gouv.fr> *)

open Types
open ParsingEngine
open Mrt


let _ =
  let pstate = pstate_of_channel "(stdin)" stdin in
  let count_headers = ref 0 in
  try
    while not (eos pstate) do
      ignore (mrt_hdr pstate);
      count_headers := !count_headers + 1
    done;
    Printf.printf "%d\n" !count_headers
  with
    | OutOfBounds s ->
      output_string stderr ("Out of bounds (" ^ s ^ ")\n")
    | ParsingError (err, sev, pstate) ->
      output_string stderr ((string_of_parsing_error "Parsing error" err sev pstate) ^ "\n");;
