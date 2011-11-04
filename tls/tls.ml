open Types
open Modules
open NewParsingEngine
open TlsCommon
open TlsRecord
open TlsHandshake
open TlsAlert
open TlsChangeCipherSpec


module TlsLib = struct
  let name = "tls"

  let params = [
    param_from_int_ref "tolerance" tolerance;
    param_from_int_ref "minDisplay" minDisplay;
  ]

  let rec shallow_parse_records pstate =
    if not (eos pstate) then
      try
	let record = RecordParser.parse pstate in
	record::(shallow_parse_records pstate)
      with 
	| OutOfBounds _ | ParsingError _ -> []
    else []

  let parse input =
    let pstate = RecordModule.mk_pstate input in
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

    V_List (parse_aux merged_records)


  let functions = ["parse", NativeFun (one_value_fun parse)]
end


module TlsModule = MakeLibraryModule (TlsLib)
let _ = add_module ((module TlsModule : Module))
