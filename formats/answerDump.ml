module AnswerDumpEngineParams = struct
  type parsing_error =
    | OutOfBounds of string
    | NotImplemented of string

  let out_of_bounds_error s = OutOfBounds s

  let string_of_perror = function
    | OutOfBounds s -> "Out of bounds (" ^ s ^ ")"
    | NotImplemented s -> "Not implemented (" ^ s ^  ")"

  let severities = [| "OK"; "Fatal" |]
end

open AnswerDumpEngineParams;;
module Engine = ParsingEngine.ParsingEngine (AnswerDumpEngineParams);;
open Engine;;


type answer_record = {
  ip : int array;
  port : int;
  name : string;
  client_hello_type : int;
  msg_type : int;
  content : string
}


let parse_answer_record pstate =
  let ip = pop_bytes pstate 4 in
  let port = extract_uint16 pstate in
  let name = extract_variable_length_string "name" extract_uint16 pstate in
  let client_hello_type = pop_byte pstate in
  let msg_type = pop_byte pstate in
  let content = extract_variable_length_string "messages" extract_uint32 pstate in
  { ip = ip; port = port; name = name; client_hello_type = client_hello_type;
    msg_type = msg_type; content = content }



let dump_answer_record answer =
  (Common.string_of_int_list (Array.to_list answer.ip)) ^
    (Common.dump_uint16 answer.port) ^
    (Common.dump_variable_length_string Common.dump_uint16 answer.name) ^
    (Common.dump_uint8 answer.client_hello_type) ^
    (Common.dump_uint8 answer.msg_type) ^
    (Common.dump_variable_length_string Common.dump_int answer.content)


let string_of_answer_record answer =
  let host = "Host " ^ (String.concat "." (List.map string_of_int (Array.to_list answer.ip))) ^
    ":" ^ (string_of_int answer.port) in
  let named_host = if String.length answer.name > 0
    then host ^ " (" ^ answer.name ^ ")"
    else host in
  let chtype = "Client Hello Type: " ^ (string_of_int answer.client_hello_type) in
  let msgtype = "Message type: " ^ (string_of_int answer.msg_type) in
  let contents = "Content: " ^ (Common.hexdump answer.content) in
  String.concat "\n" [named_host; chtype; msgtype; contents]


let pstate_of_channel = Engine.pstate_of_channel (default_error_handling_function 1 0)
let pstate_of_string = Engine.pstate_of_string (default_error_handling_function 1 0)
let pstate_of_stream = Engine.pstate_of_stream (default_error_handling_function 1 0)
