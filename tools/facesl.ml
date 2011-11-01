open Language
open Types
open Eval
open NativeFunctions

open AnswerModule
open Asn1Module
open X509Module
open TlsModule

let interactive () =
  setv [global_env] "PS1" (V_String "> ");
  try
    while true do
      print_string (getv_str [global_env] ("PS1") "> ");
      flush stdout;
      try
	let res = interpret_string [global_env] (input_line stdin) in
	print_endline (_to_string true [global_env] res);
	flush stdout
      with
	| NotImplemented -> output_string stderr "Not implemented\n"; flush stderr
	| Parsing.Parse_error -> output_string stderr ("Syntax error\n"); flush stderr
	| End_of_file -> raise End_of_file
	| e -> output_string stderr ("Unexpected error: " ^ (Printexc.to_string e) ^ "\n"); flush stderr
    done
  with End_of_file -> ()

let script_interpreter filename =
  try
    let lexbuf = Lexing.from_channel (open_in filename) in
    let ast = Parser.exprs Lexer.main_token lexbuf in
    let res = match eval_exps [global_env] ast with
      | V_Unit
      | V_Bool true -> 0
      | V_Bool false -> -1
      | V_Int i -> i
      | _ -> 0
    in exit (res)
  with
    | NotImplemented -> output_string stderr ("Not implemented\n"); exit (-2)
    | Parsing.Parse_error ->
      output_string stderr ("Syntax error\n"); exit (-2)
    | e -> output_string stderr ("Unexpected error: " ^ (Printexc.to_string e) ^ "\n"); exit (-2);;

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

