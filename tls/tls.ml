open Types
open Modules
open ParsingEngine
open TlsCommon
open TlsRecord
open TlsHandshake
open TlsAlert
open TlsChangeCipherSpec
open TlsHeartbeat


  
module TlsLib = struct
  let name = "tls"

  let params = [
    param_from_bool_ref "parse_extensions" parse_extensions;
    param_from_bool_ref "parse_certificates" parse_certificates;
  ]

  let rec shallow_parse_records pstate =
    if not (eos pstate) then
      try
	let record = RecordParser.parse pstate in
	let next_recs, error = shallow_parse_records pstate in
	record::(next_recs), error
      with 
	| OutOfBounds _ | ParsingError _ -> [], true
    else [], false

  let _deep_parse_aux name records laxist =
    let merged_records = RecordParser.merge records in

    let rec parse_aux = function
      | [] -> []
      | msg::r ->
	let parsed_content =
	  try
	    match msg.content_type with
	      | 0x14 -> [ChangeCipherSpecModule.parse [V_String name; msg.content]]
	      | 0x15 ->	[AlertModule.parse [V_String name; msg.content]]
	      | 0x16 ->	HandshakeModule.parse_all [V_String name; msg.content]
	      | 0x18 -> [HeartbeatModule.parse [V_String name; msg.content]]
	      | _ -> [msg.content]
	  with ((OutOfBounds _ | ParsingError _) as e) ->
	    if laxist
	    then [msg.content]
	    else raise e
	in
	let mk_new_record x = { msg with content = x }
	in (List.map mk_new_record parsed_content)@(parse_aux r)
    in
    parse_aux merged_records


  let _deep_parse name records error =
    let parsed_recs = _deep_parse_aux name records true in
    let res = List.map RecordModule.register parsed_recs in
    if (error)
    (* TODO: Improve perfs by removing those stupid @ ? *)
    then res@[V_Unit]
    else res

  let _parse pstate =
    let records, error = shallow_parse_records pstate in
    _deep_parse pstate.cur_name records error

  let parse input =
    let pstate = pstate_of_value_list input in
    V_List (_parse pstate)

  let deep_parse record_list =
    let records = List.map RecordModule.pop_object (eval_as_list record_list) in
    V_List (_deep_parse "(inline records)" records false)

  let functions = [
    "parse", NativeFun parse;
    "deep_parse", NativeFun (one_value_fun deep_parse);
    "mk_protocol_version", NativeFun (one_value_fun make_protocol_version);
    "mk_cipher_suite", NativeFun (one_value_fun make_cipher_suite);
    "mk_compression_method", NativeFun (one_value_fun make_compression_method)
  ]
end


module TlsModule = MakeLibraryModule (TlsLib)
let _ = add_library_module ((module TlsModule : Module))
