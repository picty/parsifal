open MapEval
open MapNativeFunctions
open Common
open AnswerDump
open AnswerDump.Engine
open AnswerDump.AnswerDumpEngineParams

let module_name = "answer_dump"
let module_fields : (string, value) Hashtbl.t = Hashtbl.create 10


let _parse pstate =
  begin
    try
      let answer = parse_answer_record pstate in
      let answer_object = Hashtbl.create 10 in
      Hashtbl.replace answer_object "dict_type" (V_String module_name);
      Hashtbl.replace answer_object "ip" (V_String (Common.string_of_ip answer.ip));
      Hashtbl.replace answer_object "port" (V_Int answer.port);
      Hashtbl.replace answer_object "name" (V_String answer.name);
      Hashtbl.replace answer_object "client_hello_type" (V_Int answer.client_hello_type);
      Hashtbl.replace answer_object "msg_type" (V_Int answer.msg_type);
      Hashtbl.replace answer_object "content" (V_BinaryString answer.content);
      V_Dict answer_object
  with
    | AnswerDump.Engine.ParsingError (err, sev, pstate) ->
      output_string stderr ("Answer parsing error: " ^ (AnswerDump.Engine.string_of_exception err sev pstate) ^ "\n");
      flush stderr;
      V_Unit
  end


let mk_ehf () =
  let tolerance = eval_as_int (Hashtbl.find module_fields "tolerance")
  and minDisplay = eval_as_int (Hashtbl.find module_fields "minDisplay") in
  default_error_handling_function tolerance minDisplay

let _parse_stream name stream =
  let pstate = pstate_of_stream (mk_ehf ()) name stream in
  _parse pstate

let _parse_string s =
  let pstate = pstate_of_string (mk_ehf ()) "(inline)" s in
  _parse pstate

let parse_string = function
  | V_BinaryString s
  | V_String s -> _parse_string s
  | _ -> raise (ContentError "String or stream expected")

let parse_stream = function
  | V_Stream (filename, s) -> _parse_stream filename s
  | _ -> raise (ContentError "String or stream expected")

let parse = function
  | V_String s -> _parse_string s
  | V_Stream (filename, s) -> _parse_stream filename s
  | _ -> raise (ContentError "String or stream expected")


let add_field field_name field_value =
  Hashtbl.replace module_fields field_name field_value

let ovf f = V_Function (NativeFun (one_value_fun f))

let init_module () =
  add_field "tolerance" (V_Int 1);
  add_field "minDisplay" (V_Int 0);
  add_field "of_string" (ovf parse_string);
  add_field "of_stream" (ovf parse_stream);
  add_field "parse" (ovf parse)
(*  add_field "dump" (V_Function (NativeFun dump))
  add_field "toString" (V_Function (NativeFun toString)) *)


let _ =
  init_module ();
  add_module module_name module_fields
