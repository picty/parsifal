open X509Directory;;
open MapLang;;
open MapNativeFunctions;;

let main () =
  Hashtbl.add global_env "PS1" (V_String "> ");
  try
    while true do
      print_string (eval_as_string (Hashtbl.find global_env ("PS1")));
      flush stdout;
      try
	let line = input_line stdin in
	let lexbuf = Lexing.from_string line in
	let result = MapParser.exprs MapLexer.main_token lexbuf in
	begin
	  try
	    let res = match eval_exps [global_env] result with
	      | (V_Bool _ | V_Int _ | V_String _ | V_List _) as value ->
		eval_as_string value
	      | V_Unit -> "OK."
	      | v -> "<" ^ string_of_type (v) ^ ">"
	    in
	    print_endline res;
	    flush stdout
	  with
	    | Asn1.Engine.ParsingError (err, sev, pstate) ->
	      output_string stderr ((Asn1.Engine.string_of_exception err sev pstate) ^ "\n"); flush stderr
	    | NotImplemented -> output_string stderr ("Not implemented\n"); flush stderr
	    | e -> output_string stderr ("Unexpected error: " ^ (Printexc.to_string e) ^ "\n"); flush stderr
	end;
	flush stdout
      with Parsing.Parse_error ->
	output_string stderr ("Syntax error\n"); flush stderr
    done
  with End_of_file -> ()
in

Printexc.print main ()
