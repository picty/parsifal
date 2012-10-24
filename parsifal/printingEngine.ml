(* Integer printing *)

let print_uint8 ?indent:(indent="") ?name:(name="uint8") v =
  Printf.sprintf "%s%s: %d (%2.2x)\n" indent name v v

let print_uint16 ?indent:(indent="") ?name:(name="uint16") v =
  Printf.sprintf "%s%s: %d (%4.4x)\n" indent name v v

let print_uint24 ?indent:(indent="") ?name:(name="uint24") v =
  Printf.sprintf "%s%s: %d (%6.6x)\n" indent name v v

let print_uint32 ?indent:(indent="") ?name:(name="uint32") v =
  Printf.sprintf "%s%s: %d (%8.8x)\n" indent name v v

let print_char ?indent:(indent="") ?name:(name="char") c =
  Printf.sprintf "%s%s: %c (%2.2x)\n" indent name c (int_of_char c)

let print_enum string_of_val int_of_val nchars ?indent:(indent="") ?name:(name="enum") v =
  Printf.sprintf "%s%s: %s (%*.*x)\n" indent name (string_of_val v) nchars nchars (int_of_val v)


(* String printing *)

let print_string ?indent:(indent="") ?name:(name="string") = function
  | "" -> Printf.sprintf "%s%s\n" indent name
  | s  -> Printf.sprintf "%s%s: \"%s\"\n" indent name (Common.quote_string s)

let print_binstring ?indent:(indent="") ?name:(name="binstring") = function
  | "" -> Printf.sprintf "%s%s\n" indent name
  | s -> Printf.sprintf "%s%s: %s\n" indent name (Common.hexdump s)


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
