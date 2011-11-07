open Types
open Modules
open ParsingEngine

type answer_dump = {
  ip : int array;
  port : int;
  name : string;
  client_hello_type : int;
  msg_type : int;
  content : string
}

module AnswerDumpParser = struct
  type t = answer_dump

  let name = "answer_dump"
  let params = []

  let parse pstate =
    let ip = Array.of_list (pop_bytes pstate 4) in
    let port = extract_uint16 pstate in
    let name = extract_variable_length_string "name" extract_uint16 pstate in
    let client_hello_type = pop_byte pstate in
    let msg_type = pop_byte pstate in
    let content = extract_variable_length_string "messages" extract_uint32 pstate in
    { ip = ip; port = port; name = name; client_hello_type = client_hello_type;
      msg_type = msg_type; content = content }

  let dump answer  =
    (Common.string_of_int_list (Array.to_list answer.ip)) ^
      (Common.dump_uint16 answer.port) ^
      (Common.dump_variable_length_string Common.dump_uint16 answer.name) ^
      (Common.dump_uint8 answer.client_hello_type) ^
      (Common.dump_uint8 answer.msg_type) ^
      (Common.dump_variable_length_string Common.dump_int answer.content)

  let enrich answer dict =
    Hashtbl.replace dict "ip" (V_String (Common.string_of_ip answer.ip));
    Hashtbl.replace dict "port" (V_Int answer.port);
    Hashtbl.replace dict "name" (V_String answer.name);
    Hashtbl.replace dict "client_hello_type" (V_Int answer.client_hello_type);
    Hashtbl.replace dict "msg_type" (V_Int answer.msg_type);
    Hashtbl.replace dict "content" (V_BinaryString answer.content)

  let update dict =
    { ip = Common.ip_of_string (eval_as_string (Hashtbl.find dict "ip"));
      port = eval_as_int (Hashtbl.find dict "port");
      name = eval_as_string (Hashtbl.find dict "name");
      client_hello_type = eval_as_int (Hashtbl.find dict "client_hello_type");
      msg_type = eval_as_int (Hashtbl.find dict "msg_type");
      content = eval_as_string (Hashtbl.find dict "content"); }

  let to_string answer =
    let host = "Host " ^ (String.concat "." (List.map string_of_int (Array.to_list answer.ip))) ^
      ":" ^ (string_of_int answer.port) in
    let named_host = if String.length answer.name > 0
      then host ^ " (" ^ answer.name ^ ")"
      else host in
    let chtype = "Client Hello Type: " ^ (string_of_int answer.client_hello_type) in
    let msgtype = "Message type: " ^ (string_of_int answer.msg_type) in
    let contents = "Content: " ^ (Common.hexdump answer.content) in
    let strcontent = [named_host; chtype; msgtype; contents] in
    Printer.PrinterLib._string_of_strlist (Some "Answer") Printer.indent_only strcontent

end

let _ =
  add_module ((module (MakeParserModule (AnswerDumpParser)) : Module))
