open Types
open Modules


module AnswerDumpParser = struct
  type t = AnswerDump.answer_record
  let name = "answer_dump"
  let params = [
    param_from_int_ref "_tolerance" AnswerDump.Engine.tolerance;
    param_from_int_ref "_minDisplay" AnswerDump.Engine.minDisplay;
  ]


  let parse name stream =
    let pstate = AnswerDump.Engine.pstate_of_stream name stream in
    try
      Some (AnswerDump.parse_answer_record pstate)
    with 
      | ParsingEngine.OutOfBounds s ->
	output_string stderr ("Out of bounds in " ^ s ^ ")");
	flush stderr;
	None
      | AnswerDump.Engine.ParsingError (err, sev, pstate) ->
	output_string stderr ("Parsing error: " ^ (AnswerDump.Engine.string_of_exception err sev pstate) ^ "\n");
	flush stderr;
	None

  let dump = AnswerDump.dump_answer_record

  let enrich answer dict =
    Hashtbl.replace dict "ip" (V_String (Common.string_of_ip answer.AnswerDump.ip));
    Hashtbl.replace dict "port" (V_Int answer.AnswerDump.port);
    Hashtbl.replace dict "name" (V_String answer.AnswerDump.name);
    Hashtbl.replace dict "client_hello_type" (V_Int answer.AnswerDump.client_hello_type);
    Hashtbl.replace dict "msg_type" (V_Int answer.AnswerDump.msg_type);
    Hashtbl.replace dict "content" (V_BinaryString answer.AnswerDump.content)

  let update dict =
    { AnswerDump.ip = Common.ip_of_string (eval_as_string (Hashtbl.find dict "ip"));
      AnswerDump.port = eval_as_int (Hashtbl.find dict "port");
      AnswerDump.name = eval_as_string (Hashtbl.find dict "name");
      AnswerDump.client_hello_type = eval_as_int (Hashtbl.find dict "client_hello_type");
      AnswerDump.msg_type = eval_as_int (Hashtbl.find dict "msg_type");
      AnswerDump.content = eval_as_string (Hashtbl.find dict "content"); }

  let to_string = AnswerDump.string_of_answer_record
end

let _ =
  add_module ((module (MakeParserModule (AnswerDumpParser)) : Module))
