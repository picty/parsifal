open AnswerDump
open AnswerDump.AnswerDumpEngineParams
open AnswerDump.Engine


let pstate = pstate_of_channel (default_error_handling_function S_Fatal S_OK) "(stdin)" stdin;;

try
  while not (eos pstate) do
    let answer = parse_answer_record pstate in
    Printf.printf "%d.%d.%d.%d:%d (len = %d)\n" answer.ip.(0) answer.ip.(1) answer.ip.(2)
      answer.ip.(3) answer.port (String.length answer.content)
  done
with
  | ParsingError (err, sev, pstate) ->
    print_endline ("Fatal (" ^ (string_of_severity sev) ^ "): " ^ 
		      (string_of_perror err) ^ " in " ^ (string_of_pstate pstate));;
