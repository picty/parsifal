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


(* name, choices, default if any, name of the "Unknown" if any *)
let handle_enum choice =
  mk_ctors choice;
  mk_string_of_enum choice;
  mk_int_of_enum choice;
  mk_enum_of_int choice;
  print_newline ()


let _ =
  List.iter handle_enum enums
