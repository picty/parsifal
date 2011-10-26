open MapEval
open MapModule


module AnswerDumpParser = struct
  type t = AnswerDump.answer_record
  let name = "answer_dump"
  let params : (string, value) Hashtbl.t = Hashtbl.create 10

  let init () =
    Hashtbl.replace params "_tolerance" (V_Int 0);
    Hashtbl.replace params "_minDisplay" (V_Int 0)


  let parse name stream =
    let tolerance = eval_as_int (Hashtbl.find params "_tolerance")
    and minDisplay = eval_as_int (Hashtbl.find params "_minDisplay") in
    let ehf = AnswerDump.Engine.default_error_handling_function tolerance minDisplay in
    let pstate = AnswerDump.Engine.pstate_of_stream ehf name stream in
    try
      Some (AnswerDump.parse_answer_record pstate)
    with 
      | AnswerDump.Engine.ParsingError (err, sev, pstate) ->
	output_string stderr ("Parsing error: " ^ (AnswerDump.Engine.string_of_exception err sev pstate) ^ "\n");
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
  add_module ((module (Make (AnswerDumpParser)) : MapModule))
