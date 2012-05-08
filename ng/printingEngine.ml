(* Integer printing *)

let print_uint sz indent name v =
  let size = sz / 4 in
  Printf.sprintf "%s%s: %d (%*.*x)\n" indent name v size size v

let print_char indent name c =
  Printf.sprintf "%s%s: %c (%2.2x)\n" indent name c (int_of_char c)

let print_enum string_of_val int_of_val sz indent name v =
  let size = sz / 4 in
  Printf.sprintf "%s%s: %s (%*.*x)\n" indent name (string_of_val v) size size (int_of_val v)


(* String printing *)

let print_string indent name s =
  Printf.sprintf "%s%s: \"%s\"\n" indent name (Common.quote_string s)

let print_binstring indent name s =
  Printf.sprintf "%s%s: %s\n" indent name (Common.hexdump s)

let print_ipv4 indent name s =
  let elts = [s.[0]; s.[1]; s.[2]; s.[3]] in
  let res = String.concat "." (List.map (fun e -> string_of_int (int_of_char e)) elts) in
  Printf.sprintf "%s%s: %s\n" indent name res

let print_ipv6 indent name s =
  failwith "Not implemented: print_ipv6"


(* List printing *)

let print_list print_fun indent name l =
  (Printf.sprintf "%s%s {\n" indent name) ^
  (String.concat "" (List.map (fun x -> print_fun (indent ^ "  ") name x) l)) ^
  (Printf.sprintf "%s}\n" indent)