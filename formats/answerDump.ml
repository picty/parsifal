open Types
open ParsingEngine
open Modules
open BinaryRecord

module AnswerDump = struct
  let name = "answer_dump"
  let description = [
    "ip", parse_ipv4, eval_as_ipv4;
    "port", parse_uint16, dumpv_uint16;
    "name", parse_varlen_string pop_uint16, eval_as_string;
    "client_hello_type", parse_uint8, dumpv_uint8;
    "msg_type", parse_uint8, dumpv_uint8;
    "content", parse_varlen_bin_string pop_uint32, eval_as_string
  ]
end

let _ = add_object_module ((module (MakeParserModule (MakeBinaryRecordParserInterface (AnswerDump))) : ObjectModule))
