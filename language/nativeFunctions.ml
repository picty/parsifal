open Common
open Types
open Printer
open Modules
open Eval


(* Generic functions *)

let typeof v = V_String (string_of_type v)

let to_string input = V_String (PrinterLib.string_of_value input)

let print args =
  print_string ((String.concat !PrinterLib.separator (List.map (PrinterLib.string_of_value) args)) ^ !PrinterLib.endline);
  V_Unit

let length = function
  | V_Bigint s ->
    let n = String.length s in
    if n > 1 && (s.[0] = '\x00' || s.[0] = '\xff')
    then V_Int ((n-1) * 8)
    else V_Int (n * 8)
  | V_BinaryString s
  | V_String s -> V_Int (String.length s)
  | V_BitString (n, s) -> V_Int ((String.length s) * 8 - n)
  | V_List l -> V_Int (List.length l)
  | _ -> raise (ContentError "String or list expected")

let as_hexa_int n_digits i =
  V_String (hexdump_int (eval_as_int n_digits) (eval_as_int i))

let error_msg fatal msg =
  output_string stderr ((eval_as_string msg) ^ "\n");
  flush stderr;
  if fatal then raise (Exit (V_Int (-1))) else V_Unit


(* Type conversion *)

let mk_bigint v = V_Bigint (eval_as_string v)
let mk_bitstring v1 v2 = V_BitString (eval_as_int v1, eval_as_string v2)

let mk_ipv4 v =
  let ip_from_list = function
    | [i0;i1;i2;i3] ->
      let res = String.make 4 (char_of_int i0) in
      res.[1] <- char_of_int i1;
      res.[2] <- char_of_int i2;
      res.[3] <- char_of_int i3;
      V_IPv4 res
    | _ -> raise (ContentError "Invalid IPv4 value")
  in
  match v with
    | V_BinaryString s | V_IPv4 s -> V_IPv4 s
    | V_List l -> ip_from_list (List.map eval_as_int l)
    | V_String s -> ip_from_list (List.map int_of_string (string_split '.' s))
    | _ -> raise (ContentError "Invalid IPv4 value")


(* Environment handling *)
let current_environment env =
  V_List (List.map (function d -> V_Dict d) env)



(* List and set functions *)

let head l = match (eval_as_list l) with
  | [] -> raise ListTooShort
  | h::_ -> h

let tail l = match (eval_as_list l) with
  | [] -> raise ListTooShort
  | _::r -> V_List r

let nth n v = get_index v n

let import_list arg =
  let rec import_aux_stream accu s =
    if eos s
    then V_List (List.rev accu)
    else import_aux_stream ((V_String (pop_line s))::accu) s
  in
  match arg with
    | V_List l -> V_List l
    | V_Stream (_, s, _) -> import_aux_stream [] s
    | v -> V_List ([v])

let rev l = V_List (List.rev (eval_as_list l))

let range vl =
  let rec range_aux accu current max =
    if current < max
    then range_aux ((V_Int current)::accu) (current+1) max
    else V_List (List.rev accu)
  in
  match vl with
    | [v1] -> range_aux [] 0 (eval_as_int v1)
    | [v1; v2] -> range_aux [] (eval_as_int v1) (eval_as_int v2)
    | _ -> raise (ContentError ("range expects one or two integer as arguments"))


let import_set args =
  let res = Hashtbl.create 10 in
  let add_string s = Hashtbl.replace res s V_Unit in
  let add_value s = Hashtbl.replace res (eval_as_string s) V_Unit in
  let rec aux = function
    | [] -> V_Dict res
    | (V_List l)::r -> List.iter add_value l; aux r
    | (V_Stream (_, s, _))::r ->
      while not (eos s) do
	add_string (pop_line s)
      done;
      aux r
    | v::r -> add_value v; aux r
  in aux args


(* Dict functions *)

let hash_make args =
  let size = match args with
    | [] -> 20
    | [n] -> eval_as_int (n)
    | _ -> raise WrongNumberOfArguments
  in
  V_Dict (Hashtbl.create (size))

let hash_get h f = get_field h (eval_as_string f)
let hash_get_def h f v = try hash_get h f with NotFound _ -> v
let hash_get_all h f = get_field_all h (eval_as_string f)
let hash_set append h f v = set_field append h (eval_as_string f) v
let hash_unset h f = unset_field h (eval_as_string f)

let make_lookup input =
  let res = Hashtbl.create 10 in
  let n, s, _ = eval_as_stream input in
  while not (eos s) do
    let line = pop_line s in
    let key, value = 
      try
	let index = String.index line ',' in
	String.sub line 0 index,
	String.sub line (index + 1) ((String.length line) - index - 1)
      with Not_found -> line, ""
    in
    if (String.length key) <> 0
    then Hashtbl.add res key (V_String value)
  done;
  V_Dict (res)

let print_stats env args =
  let prepare_aux preprocess k v accu = (eval_as_int v, preprocess k)::accu in
  let preprocess f k = eval_function env (eval_as_function f) [V_String k] in
  let lookup dict preprocess k =
    let k' = preprocess k in
    hash_find_default dict (eval_as_string k') k'
  in
  let list = match args with
  | [dict] ->
    Hashtbl.fold (prepare_aux (fun x -> V_String x)) (eval_as_dict dict) []
  | [dict; preprocess_fun] ->
    Hashtbl.fold (prepare_aux (preprocess preprocess_fun)) (eval_as_dict dict) []
  | [dict; preprocess_fun; lookup_table] ->
    let preprocess_aux = lookup (eval_as_dict lookup_table) (preprocess preprocess_fun) in
    Hashtbl.fold (prepare_aux preprocess_aux) (eval_as_dict dict) []
  | _ -> raise WrongNumberOfArguments
  in
  (* TODO Possibility to provide an order? *)
  let sorted_list = List.sort (fun (a, _) -> fun (b, _) -> - (compare a b)) list in
  let print_elt (n, k) = print_endline ((string_of_int n) ^ "\t" ^ (eval_as_string k)) in
  List.iter print_elt sorted_list;
  V_Unit



(* Iterable functions *)

let filter env f arg =
  let real_f = eval_as_function f in
  match arg with
    | V_List l ->
      let filter_aux elt = eval_as_bool (eval_function env real_f [elt]) in
      V_List (List.filter filter_aux l)
    | V_Dict d ->
      let res = Hashtbl.create (Hashtbl.length d) in
      let add_elt k v =
	if eval_as_bool (eval_function env real_f [V_String k])
	then Hashtbl.replace res k v
      in
      Hashtbl.iter add_elt d;
      V_Dict res
    | _ -> raise (ContentError "Iterable value expected")

let map env f l =
  let real_f = eval_as_function f in
  let real_l = eval_as_list l in
  V_List (List.map (fun elt -> eval_function env real_f [elt]) real_l)

let iter env f arg =
  let real_f = eval_as_function f in
  let iter_aux elt = ignore (eval_function env real_f [elt]) in
  let iter_aux_dict preprocess k v = ignore (eval_function env real_f [preprocess k; v]) in
  begin
    match arg with
      | V_List l -> List.iter iter_aux l
      | V_Dict d -> Hashtbl.iter (iter_aux_dict (fun x -> V_String x)) d
      | _ -> raise (ContentError "Iterable value expected")
  end;
  V_Unit

let iteri env f arg =
  let real_f = eval_as_function f in
  let fun_aux i elt = ignore (eval_function env real_f [V_Int i; elt]) in
  let rec iteri_aux i = function
    | [] -> V_Unit
    | elt::r -> fun_aux i elt; iteri_aux (i+1) r
  in iteri_aux 0 (eval_as_list arg)

let foreach env resource next process =
  let f_next = (eval_as_function next) in
  let f_process = (eval_as_function process) in
  while eval_as_bool (resource) do
    let obj = eval_function env f_next [resource] in
    ignore (eval_function env f_process [obj])
  done;
  V_Unit



(* File and string functions *)

let open_file filename_v =
  let filename = eval_as_string filename_v in
  let f = open_in filename in
  Gc.finalise close_in_noerr f;
  V_Stream (filename, Stream.of_channel f, Some (Unix.descr_of_in_channel f))

let open_out filename_v =
  let filename = eval_as_string filename_v in
  (* 0x1a4 = 420 = 0644 *)
  let f = open_out_gen [Open_wronly; Open_creat; Open_excl; Open_binary] 0x1a4 filename in
  Gc.finalise close_out_noerr f;
  V_OutChannel (filename, f)

let output out_v content_v =
  let (_, out_channel) = eval_as_outchannel out_v in
  let content = eval_as_string content_v in
  output_string out_channel content;
  V_Unit

let outflush out_v =
  let (_, out_channel) = eval_as_outchannel out_v in
  flush out_channel;
  V_Unit

let encode format input = match (eval_as_string format) with
  | "hex" -> V_String (hexdump (eval_as_string input))
  | _ -> raise (ContentError ("Unknown format"))

let decode format input = match (eval_as_string format) with
  | "hex" -> V_BinaryString (hexparse (eval_as_string input))
  | _ -> raise (ContentError ("Unknown format"))



(* Dynamic loading *)

let load_script env filename =
  let lexbuf = Lexing.from_channel (open_in filename) in
  let ast = Parser.exprs Lexer.main_token lexbuf in
  try eval_exps env ast
  with ReturnValue res -> res


(* OS Interface *)
let getenv varname_val =
  let varname = (eval_as_string varname_val) in
  try V_String (Unix.getenv varname)
  with Not_found -> raise (NotFound varname)





let stream_of_string n s =
  V_Stream (eval_as_string n, Stream.of_string (eval_as_string s), None)

let concat_strings sep l =
  V_String (String.concat (eval_as_string sep)
	      (List.map (fun x -> eval_as_string x) (eval_as_list l)))


(* Crypto *)

let pow x e n =
  V_Bigint (Crypto.exp_mod (eval_as_string x) (eval_as_string e) (eval_as_string n))


(* Network *)

let channels_of_socket server_addr_val port_val =
  let server_addr = eval_as_string (server_addr_val)
  and port = eval_as_int (port_val) in
  let ip_addr =
    try (Unix.gethostbyname server_addr).Unix.h_addr_list.(0)
    with Not_found -> raise (NotFound (server_addr))
  in
  let sockaddr = Unix.ADDR_INET(ip_addr, port) in
  let domain = Unix.PF_INET in
  let sock = Unix.socket domain Unix.SOCK_STREAM 0 in
  try
    Unix.connect sock sockaddr;
    Unix.set_nonblock sock;
    V_List [V_Stream (server_addr, Stream.of_channel (Unix.in_channel_of_descr sock), Some sock);
	    V_OutChannel (server_addr, Unix.out_channel_of_descr sock)]
  with exn -> Unix.close sock ; V_Unit

let wait_for_input in_channel duration_val =
  match eval_as_stream (in_channel) with
    | in_n, _, Some in_descr ->
      let duration = eval_as_int duration_val in
      let res, _, _ = Unix.select [in_descr] [] [] (float_of_int duration) in
      V_Bool (res <> [])
    (* TODO: is it a good choice? *)
    | _ -> V_Bool true

let wait duration_val =
  let duration = eval_as_int duration_val in
  ignore (Unix.select [] [] [] (float_of_int duration));
  V_Unit



let lift_three_to_one_string f =
  let aux a b c =
    V_BinaryString (f (eval_as_string a) (eval_as_string b) (eval_as_string c))
  in
  three_value_fun aux

let _ =
  (* Generic functions *)
  add_native "unit" (fun _ -> V_Unit);
  add_native "typeof" (one_value_fun typeof);
  add_native "to_string" (one_value_fun to_string);
  add_native "print" print;
  add_native "length" (one_value_fun length);
  add_native_with_env "eval" (one_string_fun_with_env interpret_string);
  add_native "as_hexa_int" (two_value_fun as_hexa_int);
  add_native "exit" (one_value_fun (fun v -> raise (Exit v)));
  add_native "warning" (one_value_fun (error_msg false));
  add_native "fatal_error" (one_value_fun (error_msg true));

  (* Conversion functions *)
  add_native "bigint" (one_value_fun mk_bigint);
  add_native "bitstring" (two_value_fun mk_bitstring);
  add_native "ipv4" (one_value_fun mk_ipv4);

  (* Environment handling *)
  add_native_with_env "current_environment" (zero_value_fun_with_env current_environment);

  (* List and set functions *)
  add_native "head" (one_value_fun head);
  add_native "tail" (one_value_fun tail);
  add_native "nth" (two_value_fun nth);
  add_native "list" (one_value_fun import_list);
  add_native "set" import_set;
  add_native "rev" (one_value_fun rev);
  add_native "range" range;

  (* Dict functions *)
  add_native "dict" hash_make;
  add_native "dget" (two_value_fun hash_get);
  add_native "dget_def" (three_value_fun hash_get_def);
  add_native "dget_all" (two_value_fun hash_get_all);
  add_native "dadd" (three_value_fun (hash_set true));
  add_native "dset" (three_value_fun (hash_set false));
  add_native "dunset" (two_value_fun hash_unset);
  add_native "make_lookup" (one_value_fun (make_lookup));
  add_native_with_env "print_stats" print_stats;

  (* Iterable functions *)
  add_native_with_env "filter" (two_value_fun_with_env filter);
  add_native_with_env "map" (two_value_fun_with_env map);
  add_native_with_env "iter" (two_value_fun_with_env iter);
  add_native_with_env "iteri" (two_value_fun_with_env iteri);
  add_native_with_env "foreach" (three_value_fun_with_env foreach);

  (* File and string functions *)
  add_native "open" (one_value_fun open_file);
  add_native "open_out" (one_value_fun open_out);
  Hashtbl.replace global_env "stdout" (V_OutChannel ("(stdout)", stdout));
  Hashtbl.replace global_env "stderr" (V_OutChannel ("(stderr)", stderr));
  add_native "output" (two_value_fun output);
  add_native "flush" (one_value_fun outflush);

  add_native "encode" (two_value_fun encode);
  add_native "decode" (two_value_fun decode);
  add_native "stream" (two_value_fun stream_of_string);
  add_native "concat" (two_value_fun concat_strings);

  (* Dynamic loading *)
  add_native_with_env "load" (one_string_fun_with_env load_script);

  (* OS interface *)
  add_native "getenv" (one_value_fun getenv);

  (* Crypto *)
  add_native "md5sum" (one_value_fun (fun x -> V_BinaryString (Crypto.md5sum (eval_as_string x))));
  add_native "sha1sum" (one_value_fun (fun x -> V_BinaryString (Crypto.sha1sum (eval_as_string x))));
  add_native "sha224sum" (one_value_fun (fun x -> V_BinaryString (Crypto.sha224sum (eval_as_string x))));
  add_native "sha256sum" (one_value_fun (fun x -> V_BinaryString (Crypto.sha256sum (eval_as_string x))));
  add_native "sha384sum" (one_value_fun (fun x -> V_BinaryString (Crypto.sha384sum (eval_as_string x))));
  add_native "sha512sum" (one_value_fun (fun x -> V_BinaryString (Crypto.sha512sum (eval_as_string x))));
  add_native "pow" (three_value_fun pow);

  add_native "aes_cbc_raw_encrypt" (lift_three_to_one_string Crypto.aes_cbc_raw_encrypt);
  add_native "aes_cbc_raw_decrypt" (lift_three_to_one_string Crypto.aes_cbc_raw_decrypt);
  add_native "aes_cbc_encrypt" (lift_three_to_one_string Crypto.aes_cbc_encrypt);
  add_native "aes_cbc_decrypt" (lift_three_to_one_string Crypto.aes_cbc_decrypt);

  (* Network *)
  add_native "socket" (two_value_fun channels_of_socket);
  add_native "wait_for_input" (two_value_fun wait_for_input);
  add_native "wait" (one_value_fun wait);
  ()
