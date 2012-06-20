let mk_ctors (name, enum, unknown) =
  Printf.printf "type %s =\n" name;
  let aux (_, ctor, _) = Printf.printf "  | %s\n" ctor in
  List.iter aux enum;
  begin
    match unknown with
      | UnknownVal u -> Printf.printf "  | %s of int\n" u
      | _ -> ()
  end;
  print_newline ();
  begin
    match unknown with
      | Exception e -> Printf.printf "exception %s\n\n" e
      | _ -> ()
  end

let mk_string_of_enum (name, enum, unknown) =
  Printf.printf "let string_of_%s = function\n" name;
  let aux (_, ctor, n) = Printf.printf "  | %s -> \"%s\"\n" ctor n in
  List.iter aux enum;
  begin
    match unknown with
      | UnknownVal u -> Printf.printf "  | %s _ -> \"Unknown %s\"\n" u name
      | _ -> ()
  end;
  print_newline ()

let mk_int_of_enum (name, enum, unknown) =
  Printf.printf "let int_of_%s = function\n" name;
  let aux (i, ctor, _) = Printf.printf "  | %s -> %d\n" ctor i in
  List.iter aux enum;
  begin
    match unknown with
      | UnknownVal u -> Printf.printf "  | %s i -> i\n" u
      | _ -> ()
  end;
  print_newline ()

let mk_enum_of_int (name, enum, unknown) =
  Printf.printf "let %s_of_int = function\n" name;
  let aux (i, ctor, _) = Printf.printf "  | %d -> %s\n" i ctor in
  List.iter aux enum;
  begin
    match unknown with
      | DefaultVal d -> Printf.printf "  | _ -> %s\n" d
      | UnknownVal u -> Printf.printf "  | i -> %s i\n" u
      | Exception e -> Printf.printf "  | _ -> raise %s\n" e
  end;
  print_newline ()

let mk_parse_dump_print_funs do_lwt (name, _, _) =
  Printf.printf "let parse_%s parse_int input = %s_of_int (parse_int input)\n" name name;
  if do_lwt
  then Printf.printf "let lwt_parse_%s lwt_parse_int input = lwt_parse_int input >>= fun x -> return (%s_of_int x)\n" name name;
  Printf.printf "let dump_%s dump_int v = dump_int (int_of_%s v)\n" name name;
  Printf.printf "let print_%s = print_enum string_of_%s int_of_%s\n" name name name


let handle_enum do_lwt (enum : enum) =
  mk_ctors enum;
  mk_string_of_enum enum;
  mk_int_of_enum enum;
  mk_enum_of_int enum;
  mk_parse_dump_print_funs do_lwt enum;
  print_newline ()


let _ =
  let do_lwt = true in
  if do_lwt then print_endline "open Lwt";
  print_endline "open PrintingEngine\n";
  List.iter (handle_enum do_lwt) enums
