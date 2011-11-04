open Types
open Modules
open ParsingEngine
open TlsCommon
open TlsRecord
open TlsHandshake
open TlsAlert
open TlsChangeCipherSpec


module TlsLib = struct
  let name = "tls"

  let params = []

  let rec shallow_parse_records pstate =
    if not (eos pstate) then
      try
	let record = RecordParser.parse pstate in
	record::(shallow_parse_records pstate)
      with 
	| OutOfBounds _ | ParsingError _ -> []
    else []

  let _parse pstate =
    let records = shallow_parse_records pstate in
    let merged_records = RecordParser.merge records in

    let rec parse_aux = function
      | [] -> []
      | msg::r ->
	let parsed_content = match msg.content_type with
	  | CT_ChangeCipherSpec ->
	    [ChangeCipherSpecModule.parse msg.content]
	  | CT_Alert ->
	    [AlertModule.parse msg.content]
	  | CT_Handshake ->
	    HandshakeModule.parse_all msg.content
	  | _ -> [msg.content]
	in
	let mk_new_record x = RecordModule.register { msg with content = x }
	in (List.map mk_new_record parsed_content)@(parse_aux r)
    in

    parse_aux merged_records

  let parse input =
    let pstate = pstate_of_value input in
    V_List (_parse pstate)


  let functions = ["parse", NativeFun (one_value_fun parse)]
end


module TlsModule = MakeLibraryModule (TlsLib)
let _ = add_module ((module TlsModule : Module))
