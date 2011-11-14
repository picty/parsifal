open Language
open Types
open Printer
open Eval
open NativeFunctions

open AnswerDump
open Tls

open Asn1
open X509

open Mrt


let string_of_pos pos1 pos2 =
  "File \"" ^ pos1.Lexing.pos_fname ^ "\", line " ^
    (string_of_int pos1.Lexing.pos_lnum) ^ ", characters " ^
    (string_of_int (pos1.Lexing.pos_cnum - pos1.Lexing.pos_bol)) ^ "-" ^
    (string_of_int (pos2.Lexing.pos_cnum - pos2.Lexing.pos_bol))

let err msg =
  output_string stderr (msg ^ "\n");
  flush stderr;
  V_Int (-2)


let interactive_loop () =
  setv [global_env] "PS1" (V_String "> ");
  try
    while true do
      print_string (getv_str [global_env] ("PS1") "> ");
      flush stdout;
      try
	let res = interpret_string [global_env] (input_line stdin) in
	if res != V_Unit
	then print_endline (String.concat "\n" (PrinterLib._string_of_value None true res));
	flush stdout
      with
	| NotImplemented -> output_string stderr "Not implemented\n"; flush stderr
	| Parsing.Parse_error -> output_string stderr ("Syntax error\n"); flush stderr
	| End_of_file -> raise End_of_file

	(* HACK *)
	| ParsingEngine.OutOfBounds s ->
	  output_string stderr ("Out of bounds in " ^ s ^ "\n");
	  flush stderr
	| ParsingEngine.ParsingError (err, sev, pstate) ->
	  output_string stderr ((ParsingEngine.string_of_parsing_error "Parsing error" err sev pstate));
	  flush stderr

	| e -> output_string stderr ("Unexpected error: " ^ (Printexc.to_string e) ^ "\n"); flush stderr
    done
  with End_of_file -> ()


let script_interpreter filename =
  let retval =
    try
      let lexbuf = Lexing.from_channel (open_in filename) in
      try
	let ast = Parser.exprs Lexer.main_token lexbuf in
	eval_exps [global_env] ast
      with
	| Exit res | ReturnValue res -> res
	| NotImplemented -> err "Not implemented\n"
	| Parsing.Parse_error ->
	  err ("Syntax error (" ^ (string_of_pos lexbuf.Lexing.lex_start_p
				     lexbuf.Lexing.lex_curr_p) ^ "): \"" ^
	  (Lexing.lexeme lexbuf) ^ "\"")
    with e -> err ("Unexpected error: " ^ (Printexc.to_string e))
  in 
  match retval with
    | V_Unit
    | V_Bool true -> 0
    | V_Bool false -> -1
    | V_Int i -> i
    | _ -> 0


let rec load_files = function
  | [] -> 0
  | [f] -> script_interpreter f
  | f::r -> ignore (script_interpreter f); load_files r


let _ =
  let interactive = ref false in
  let files = ref [] in
  let args = ref [] in

  let add_input s = files := s::(!files) in
  let add_arg s = args := (V_String s)::(!args) in
  let options = [
    ("-i", Arg.Set interactive, "Interactive mode");
    ("-f", Arg.String add_input, "File to load");
  ] in

  Arg.parse options add_arg "facesl [-i] [-f <file>] args";
  setv [global_env] "args" (V_List (List.rev !args));
  if !files = [] then interactive := true;

  let res = load_files (List.rev !files) in
  if !interactive
  then begin
    Printexc.print interactive_loop ();
    0
  end
  else exit (res);
