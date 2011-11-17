open Common
open Types
open ParsingEngine
open BinaryRecord
open AnswerDump


let get_name answer =
  let name = eval_as_string (answer --> "name") in
  if String.length name = 0
  then Common.string_of_ip4 (eval_as_ipv4 (answer --> "ip"))
  else name

let _ =
  let pstate = pstate_of_channel "(stdin)" stdin in

  TlsHandshake.parse_certificates := true;

  try
    while not (eos pstate) do
      let answer = BinaryRecord.parse AnswerDump.description pstate in
      let name = get_name answer in
      Printf.printf "%s:\n" name;
      (* TODO: Keep the history? *)
      let tls_pstate = pstate_of_string (Some name) (eval_as_string (answer --> "content")) in

      let tls_msgs = List.map TlsRecord.RecordModule.pop_object (Tls.TlsLib._parse tls_pstate) in

      List.iter (fun x -> Printf.printf "  %s\n" (String.concat "\n  " (TlsRecord.RecordParser.to_string x))) tls_msgs;
      print_newline ()
    done
  with
    | OutOfBounds s ->
      output_string stderr ("Out of bounds (" ^ s ^ ")\n")
    | ParsingError (err, sev, pstate) ->
      output_string stderr ((string_of_parsing_error "Parsing error" err sev pstate) ^ "\n");;
