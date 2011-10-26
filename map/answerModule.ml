open MapEval
open MapModule


module AnswerDumpParser = struct
  type t = AnswerDump.answer_record

  let name = "answer_dump"
  let default_tolerance = 0
  let default_minDisplay = 0

  let parse tolerance minDisplay name stream =
    let ehf = AnswerDump.Engine.default_error_handling_function tolerance minDisplay in
    let pstate = AnswerDump.Engine.pstate_of_stream ehf name stream in
    AnswerDump.parse_answer_record pstate

  let dump = AnswerDump.dump_answer_record

  let enrich enricher answer dict =
    Hashtbl.replace dict "ip" (enricher.to_string (Common.string_of_ip answer.AnswerDump.ip));
    Hashtbl.replace dict "port" (enricher.to_int answer.AnswerDump.port);
    Hashtbl.replace dict "name" (enricher.to_string answer.AnswerDump.name);
    Hashtbl.replace dict "client_hello_type" (enricher.to_int answer.AnswerDump.client_hello_type);
    Hashtbl.replace dict "msg_type" (enricher.to_int answer.AnswerDump.msg_type);
    Hashtbl.replace dict "content" (enricher.to_binary_string answer.AnswerDump.content)

  let update enricher dict =
    { AnswerDump.ip = Common.ip_of_string (enricher.of_string (Hashtbl.find dict "ip"));
      AnswerDump.port = enricher.of_int (Hashtbl.find dict "port");
      AnswerDump.name = enricher.of_string (Hashtbl.find dict "name");
      AnswerDump.client_hello_type = enricher.of_int (Hashtbl.find dict "client_hello_type");
      AnswerDump.msg_type = enricher.of_int (Hashtbl.find dict "msg_type");
      AnswerDump.content = enricher.of_binary_string (Hashtbl.find dict "content"); }

  let to_string = AnswerDump.string_of_answer_record
end

let _ =
  add_module ((module (Make (AnswerDumpParser)) : MapModule))
