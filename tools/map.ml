open X509Directory;;

let main () =
  let env = Hashtbl.create 100 in
  try
    while true do
      let line = input_line stdin in
      let lexbuf = Lexing.from_string line in
      let result = MapParser.commands MapLexer.main_token lexbuf in
      begin
	try
	  List.iter (MapLang.eval_command (Hashtbl.find env) (Hashtbl.replace env)) result;
	  print_endline "OK."	  
	with
	  | Asn1.Engine.ParsingError (err, sev, pstate) ->
	    output_string stderr ((Asn1.Engine.string_of_exception err sev pstate) ^ "\n"); flush stderr
	  | MapLang.NotImplemented
	  | MapLang.ExecutionStopped -> ()
	  | e -> output_string stderr ((Printexc.to_string e) ^ "\n"); flush stderr
      end;
      flush stdout
    done
  with End_of_file -> ()
in

Printexc.print main ()
