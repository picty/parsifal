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


let pstate_of_channel = Engine.pstate_of_channel (default_error_handling_function 1 0)
let pstate_of_string = Engine.pstate_of_string (default_error_handling_function 1 0)
let pstate_of_stream = Engine.pstate_of_stream (default_error_handling_function 1 0)
