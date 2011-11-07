open Types
open ParsingEngine
open AnswerDump


let get_name answer =
  if String.length answer.name = 0
  then Common.string_of_ip answer.ip
  else answer.name

let _ =
  let pstate = pstate_of_channel "(stdin)" stdin in

  TlsHandshake.parse_certificates := true;

  try
    while not (eos pstate) do
      let answer = AnswerDumpParser.parse pstate in
      let name = get_name answer in
      Printf.printf "%s:\n" name;
      (* TODO: Keep the history? *)
      let tls_pstate = pstate_of_string (Some name) answer.content in

      let tls_msgs = List.map TlsRecord.RecordModule.pop_object (Tls.TlsLib._parse tls_pstate) in

      List.iter (fun x -> Printf.printf "  %s\n" (String.concat "\n  " (TlsRecord.RecordParser.to_string x))) tls_msgs;
      print_newline ()
    done
  with
    | OutOfBounds s ->
      output_string stderr ("Out of bounds (" ^ s ^ ")\n")
    | ParsingError (err, sev, pstate) ->
      output_string stderr ((string_of_parsing_error "Parsing error" err sev pstate) ^ "\n");;
