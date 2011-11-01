open AnswerModule.AnswerDumpParser

let get_name answer =
  if String.length answer.name = 0
  then Common.string_of_ip answer.ip
  else answer.name;;

let parse_record = Tls.parse_record true;;
let ehf = mk_ehf ();;
let pstate = NewParsingEngine.pstate_of_channel ehf "(stdin)" stdin;;


try
  while not (NewParsingEngine.eos pstate) do
    match parse pstate with
      | Some answer -> begin
	let name = get_name answer in
	Printf.printf "%s:" name;
	try
	  let tls_pstate = Tls.Engine.pstate_of_string name answer.content in
	  while not (Tls.Engine.eos tls_pstate) do
	    try
	      let record = parse_record tls_pstate in begin
		match record.Tls.content with
		  | Tls.Alert _ | Tls.ChangeCipherSpec _ -> Printf.printf " %s" (Tls.string_of_record_content record.Tls.content)
		  | Tls.ApplicationData _ -> Printf.printf " ApplicationData"
		  | Tls.Handshake hm -> Printf.printf " Handshake (%s)" (Tls.string_of_handshake_msg_type (Tls.type_of_handshake_msg hm))
		  | Tls.UnparsedRecord (ct, _) ->
		    Tls.Engine.emit (Tls.TlsEngineParams.NotImplemented "SSLv2 ?")
		      ParsingEngine.s_fatal tls_pstate
	      end;
	    with
	      | ParsingEngine.OutOfBounds s ->
		output_string stderr ("Out of bounds in " ^ s ^ ")");
		flush stderr
	      | Asn1.Engine.ParsingError (err, sev, pstate) ->
		output_string stderr ("Asn1.Error " ^ (Asn1.Engine.string_of_exception err sev pstate) ^ ")\n");
		flush stderr
	  done;
	  print_newline ();
	with
	  | Tls.Engine.ParsingError (err, sev, pstate) ->
	    print_newline ();
	    output_string stderr ("Tls.Error " ^ (Tls.Engine.string_of_exception err sev pstate) ^ ")\n");
      end
      | None -> failwith "Pouet"
  done
with
  | Asn1.Engine.ParsingError (err, sev, pstate) ->
    print_newline ();
    output_string stderr ("Asn1.Fatal " ^ (Asn1.Engine.string_of_exception err sev pstate) ^ ")\n")
  | Tls.Engine.ParsingError (err, sev, pstate) ->
    print_newline ();
    output_string stderr ("Tls.Fatal " ^ (Tls.Engine.string_of_exception err sev pstate) ^ ")\n");;
