open Types
open ParsingEngine
open Modules
open BinaryRecord

module AnswerDump_ng = struct
  let name = "answer_dump_ng"
  let description = [
    "ip", parse_ipv4, dump_ipv4;
    "port", parse_uint16, dump_uint16;
    "name", parse_varlen_string "name" extract_uint16, dump_string;
    "client_hello_type", parse_uint8, dump_uint8;
    "msg_type", parse_uint8, dump_uint8;
    "content", parse_varlen_bin_string "content" extract_uint32, dump_string
  ]
end

let _ = add_module ((module (MakeParserModule (MakeBinaryRecordParserInterface (AnswerDump_ng))) : Module))
