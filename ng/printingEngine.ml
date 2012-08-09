(* Integer printing *)

let print_uint8 indent name v =
  Printf.sprintf "%s%s: %d (%2.2x)\n" indent name v v

let print_uint16 indent name v =
  Printf.sprintf "%s%s: %d (%4.4x)\n" indent name v v

let print_uint24 indent name v =
  Printf.sprintf "%s%s: %d (%6.6x)\n" indent name v v

let print_uint32 indent name v =
  Printf.sprintf "%s%s: %d (%8.8x)\n" indent name v v

let print_char indent name c =
  Printf.sprintf "%s%s: %c (%2.2x)\n" indent name c (int_of_char c)

let print_enum string_of_val int_of_val nchars indent name v =
  Printf.sprintf "%s%s: %s (%*.*x)\n" indent name (string_of_val v) nchars nchars (int_of_val v)


(* String printing *)

let print_string indent name = function
  | "" -> Printf.sprintf "%s%s\n" indent name
  | s  -> Printf.sprintf "%s%s: \"%s\"\n" indent name (Common.quote_string s)

let print_binstring indent name s =
  Printf.sprintf "%s%s: %s\n" indent name (Common.hexdump s)

let string_of_ipv4 s =
  let elts = [s.[0]; s.[1]; s.[2]; s.[3]] in
  String.concat "." (List.map (fun e -> string_of_int (int_of_char e)) elts)

let print_ipv4 indent name s =
  let res = string_of_ipv4 s in
  Printf.sprintf "%s%s: %s\n" indent name res

let print_ipv6 indent name s =
  let res = String.make 39 ':' in
  for i = 0 to 15 do
    let x = int_of_char (String.get s i) in
    res.[(i / 2) + i * 2] <- Common.hexa_char.[(x lsr 4) land 0xf];
    res.[(i / 2) + i * 2 + 1] <- Common.hexa_char.[x land 0xf];
  done;
  res


(* List printing *)

let print_list print_fun indent name l =
  (Printf.sprintf "%s%s {\n" indent name) ^
  (String.concat "" (List.map (fun x -> print_fun (indent ^ "  ") name x) l)) ^
  (Printf.sprintf "%s}\n" indent)


(* Useful function *)

let try_print print_fun indent name = function
  | None -> ""
  | Some x -> print_fun indent name x
