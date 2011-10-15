open X509Directory;;
open MapLang;;

let main () =
  let env = Hashtbl.create 100 in
  Hashtbl.add env "PS1" (V_String "> ");
  try
    while true do
      print_string (eval_as_string (Hashtbl.find env ("PS1")));
      flush stdout;
      let line = input_line stdin in
      let lexbuf = Lexing.from_string line in
      let result = MapParser.exprs MapLexer.main_token lexbuf in
      begin
	try
	  let res = match eval_exps (Hashtbl.find env) (Hashtbl.replace env) result with
	    | (V_Bool _ | V_Int _ | V_String _ | V_Certificate _) as value ->
	      eval_as_string value
	    | V_Unit -> "OK."
	    | V_Function _ -> "<fun>"
	    | V_Stream _ -> "<stream>"
	  in
	  print_endline res;
	  flush stdout
	with
	  | Asn1.Engine.ParsingError (err, sev, pstate) ->
	    output_string stderr ((Asn1.Engine.string_of_exception err sev pstate) ^ "\n"); flush stderr
	  | NotImplemented -> ()
	  | e -> output_string stderr ((Printexc.to_string e) ^ "\n"); flush stderr
      end;
      flush stdout
    done
  with End_of_file -> ()
in

Printexc.print main ()
