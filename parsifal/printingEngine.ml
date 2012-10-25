(* List printing *)

let print_list (print_fun : ?indent:string -> ?name:string -> 'a -> string) ?indent:(indent="") ?name:(name="list") l =
  (Printf.sprintf "%s%s {\n" indent name) ^
  (String.concat "" (List.map (fun x -> print_fun ~indent:(indent ^ "  ") ~name:name x) l)) ^
  (Printf.sprintf "%s}\n" indent)


(* Useful function *)

let try_print (print_fun : ?indent:string -> ?name:string -> 'a -> string) ?indent:(indent="") ?name (x:'a option) =
  match name, x with
  | _, None -> ""
  | None, Some x -> print_fun ~indent:indent x
  | Some n, Some x -> print_fun ~indent:indent ~name:n x
