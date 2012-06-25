let mk_module_prefix = function
  | None -> ""
  | Some module_name -> module_name ^ "."

let mk_choice_type (name, _, choices, unparsed_cons) =
  Printf.printf "let enrich_%s = ref true\n\n" name;
  Printf.printf "type %s =\n" name;
  let aux (_, cons, type_mod, type_name) =
    Printf.printf "  | %s of %s%s\n" cons (mk_module_prefix type_mod) type_name
  in
  List.iter aux choices;
  Printf.printf "  | %s of string\n\n" unparsed_cons


let mk_parse_fun (name, discr_module, choices, unparsed_cons) =
  Printf.printf "let parse_%s ?context:(ctx=None) discriminator input =\n" name;
  Printf.printf "  if !enrich_%s then begin\n" name;
  Printf.printf "    match discriminator with\n";
  let aux (discr_value, cons, type_mod, type_name) =
    Printf.printf "      | %s%s -> %s (%sparse_%s ~context:ctx input)\n"
      (mk_module_prefix discr_module) discr_value cons (mk_module_prefix type_mod) type_name
  in
  List.iter aux choices;
  Printf.printf "      | _ -> %s (parse_rem_string input)\n" unparsed_cons;
  Printf.printf "  end else %s (parse_rem_string input)\n\n" unparsed_cons

let mk_dump_fun (name, _, choices, unparsed_cons) =
  Printf.printf "let dump_%s = function\n" name;
  let aux (_, cons, type_mod, type_name) =
    Printf.printf "  | %s x -> %sdump_%s x\n" cons (mk_module_prefix type_mod) type_name
  in
  List.iter aux choices;
  Printf.printf "  | %s s -> s\n\n" unparsed_cons

let mk_print_fun (name, _, choices, unparsed_cons) =
  Printf.printf "let print_%s indent name = function\n" name;
  let aux (_, cons, type_mod, type_name) =
    Printf.printf "  | %s x -> %sprint_%s indent name x\n" cons (mk_module_prefix type_mod) type_name
  in
  List.iter aux choices;
  Printf.printf "  | %s s -> print_binstring indent name s\n\n" unparsed_cons


let handle_choice (choice : choice) =
  mk_choice_type choice;
  mk_parse_fun choice;
(*  if do_lwt then mk_lwt_parse_fun desc; *)
  mk_dump_fun choice;
  mk_print_fun choice;
  print_newline ()


let _ =
(*  let do_lwt = true in
  if do_lwt then begin
    print_endline "open Lwt";
    print_endline "open LwtParsingEngine"
  end; *)
  print_endline "open ParsingEngine";
  print_endline "open DumpingEngine";
  print_endline "open PrintingEngine\n";
  List.iter handle_choice choices
