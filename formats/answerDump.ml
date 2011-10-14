module AnswerDumpEngineParams = struct
  type parsing_error =
    | OutOfBounds of string
    | NotImplemented of string

  let out_of_bounds_error s = OutOfBounds s

  let string_of_perror = function
    | OutOfBounds s -> "Out of bounds (" ^ s ^ ")"
    | NotImplemented s -> "Not implemented (" ^ s ^  ")"

  type severity =
    | S_OK
    | S_Fatal

  let fatal_severity = S_Fatal

  let string_of_severity = function
    | S_OK -> "OK"
    | S_Fatal -> "Fatal"

  let int_of_severity = function
    | S_OK -> 0
    | S_Fatal -> 2

  let compare_severity x y =
    compare (int_of_severity x) (int_of_severity y)
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
  
    
