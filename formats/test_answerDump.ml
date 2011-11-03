(* TODO *)

failwith "TODO: Rewrite!"

(*
open AnswerModule.AnswerDumpParser

let get_name answer =
  if String.length answer.name = 0
  then Common.string_of_ip answer.ip
  else answer.name;;

let parse_record = OldTls.parse_record true;;
let ehf = mk_ehf ();;
let pstate = NewParsingEngine.pstate_of_channel ehf "(stdin)" stdin;;


try
  while not (NewParsingEngine.eos pstate) do
    match parse pstate with
      | Some answer -> begin
	let name = get_name answer in
	Printf.printf "%s:" name;
	try
	  let tls_pstate = OldTls.Engine.pstate_of_string name answer.content in
	  while not (OldTls.Engine.eos tls_pstate) do
	    try
	      let record = parse_record tls_pstate in begin
		match record.OldTls.content with
		  | OldTls.Alert _ | OldTls.ChangeCipherSpec _ -> Printf.printf " %s" (OldTls.string_of_record_content record.OldTls.content)
		  | OldTls.ApplicationData _ -> Printf.printf " ApplicationData"
		  | OldTls.Handshake hm ->
		    Printf.printf " Handshake (%s)"
		      (String.concat (", ") (List.map (fun m -> OldTls.string_of_handshake_msg_type (OldTls.type_of_handshake_msg m)) hm))
		  | OldTls.UnparsedRecord (ct, _) ->
		    OldTls.Engine.emit (OldTls.TlsEngineParams.NotImplemented "SSLv2 ?")
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
	  | OldTls.Engine.ParsingError (err, sev, pstate) ->
	    print_newline ();
	    output_string stderr ("OldTls.Error " ^ (OldTls.Engine.string_of_exception err sev pstate) ^ ")\n");
      end
      | None -> failwith "Pouet"
  done
with
  | Asn1.Engine.ParsingError (err, sev, pstate) ->
    print_newline ();
    output_string stderr ("Asn1.Fatal " ^ (Asn1.Engine.string_of_exception err sev pstate) ^ ")\n")
  | OldTls.Engine.ParsingError (err, sev, pstate) ->
    print_newline ();
    output_string stderr ("OldTls.Fatal " ^ (OldTls.Engine.string_of_exception err sev pstate) ^ ")\n");;
*)
