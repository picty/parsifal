open Types
open ParsingEngine
open AnswerDump

let get_name answer =
  if String.length answer.name = 0
  then Common.string_of_ip answer.ip
  else answer.name

let _ =
  let ehf = AnswerDumpParser.mk_ehf () in
  let pstate = pstate_of_channel ehf "(stdin)" stdin in

  try
    while not (eos pstate) do
      let answer = AnswerDumpParser.parse pstate in
      let name = get_name answer in
      Printf.printf "%s:\n" name;
      let tls_ehf = TlsRecord.RecordParser.mk_ehf () in
      let tls_pstate = pstate_of_string tls_ehf (Some name) answer.content in

      let tls_msgs = List.map TlsRecord.RecordModule.pop_object (Tls.TlsLib._parse tls_pstate) in

      List.iter (fun x -> Printf.printf "%s\n" (TlsRecord.RecordParser.to_string x)) tls_msgs;
      print_newline ()
    done
  with
    | OutOfBounds s ->
      output_string stderr ("Out of bounds (" ^ s ^ ")\n")
    | ParsingError (err, sev, pstate) ->
      output_string stderr ((string_of_parsing_error "Parsing error" err sev pstate) ^ "\n");;
