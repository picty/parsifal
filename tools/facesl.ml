open Language
open Types
open Printer
open Eval
open NativeFunctions

open AnswerModule
open Tls

open Asn1
open X509Module


let interactive () =
  setv [global_env] "PS1" (V_String "> ");
  try
    while true do
      print_string (getv_str [global_env] ("PS1") "> ");
      flush stdout;
      try
	let res = interpret_string [global_env] (input_line stdin) in
	print_endline (PrinterLib.string_of_value_aux "" true res);
	flush stdout
      with
	| NotImplemented -> output_string stderr "Not implemented\n"; flush stderr
	| Parsing.Parse_error -> output_string stderr ("Syntax error\n"); flush stderr
	| End_of_file -> raise End_of_file

	(* HACK *)
	| NewParsingEngine.OutOfBounds s ->
	  output_string stderr ("Out of bounds in " ^ s ^ "\n");
	  flush stderr
	| NewParsingEngine.ParsingError (err, sev, pstate) ->
	  output_string stderr ((NewParsingEngine.string_of_parsing_error "Parsing error" err sev pstate));
	  flush stderr

	| e -> output_string stderr ("Unexpected error: " ^ (Printexc.to_string e) ^ "\n"); flush stderr
    done
  with End_of_file -> ()

let script_interpreter filename =
  let retval =
    try
      let lexbuf = Lexing.from_channel (open_in filename) in
      let ast = Parser.exprs Lexer.main_token lexbuf in
      eval_exps [global_env] ast
    with
      | ReturnValue res -> res
      | NotImplemented -> output_string stderr ("Not implemented\n"); V_Int (-2)
      | Parsing.Parse_error -> output_string stderr ("Syntax error\n"); V_Int (-2)
      | e -> output_string stderr ("Unexpected error: " ^ (Printexc.to_string e) ^ "\n"); V_Int (-2)
  in 
  let res = match retval with
    | V_Unit
    | V_Bool true -> 0
    | V_Bool false -> -1
    | V_Int i -> i
    | _ -> 0
  in exit (res)


let _ =
  match Array.length (Sys.argv) with
    | 0 | 1 -> Printexc.print interactive ()
    | _ -> begin
      match Array.to_list Sys.argv with
	| [] | [_] -> ()
	| _::_::args ->
	  setv [global_env] "args" (V_List (List.map (fun s -> V_String s) args))
      end;
      script_interpreter Sys.argv.(1)

