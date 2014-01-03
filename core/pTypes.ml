open Parsifal
open BasePTypes
open Lwt


(* IPv4 and IPv6 *)

type ipv4 = string

let parse_ipv4 = parse_string 4
let lwt_parse_ipv4 = lwt_parse_string 4

let dump_ipv4 buf ipv4 = POutput.add_string buf ipv4

let string_of_ipv4 s =
  let elts = [s.[0]; s.[1]; s.[2]; s.[3]] in
  String.concat "." (List.map (fun e -> string_of_int (int_of_char e)) elts)

let value_of_ipv4 s =
  let elts = [s.[0]; s.[1]; s.[2]; s.[3]] in
  VRecord [
    "@name", VString ("ipv4", false);
    "@string_of", VString (string_of_ipv4 s, false);
    "address", VList (List.map (fun x -> VSimpleInt (int_of_char x)) elts)
  ]


type ipv6 = string

let parse_ipv6 = parse_string 16
let lwt_parse_ipv6 = lwt_parse_string 16

let dump_ipv6 buf ipv6 = POutput.add_string buf ipv6

(* TODO: Compress it! *)
let string_of_ipv6 s =
  let res = String.make 39 ':' in
  for i = 0 to 15 do
    let x = int_of_char (String.get s i) in
    res.[(i / 2) + i * 2] <- hexa_char.[(x lsr 4) land 0xf];
    res.[(i / 2) + i * 2 + 1] <- hexa_char.[x land 0xf];
  done;
  res

let value_of_ipv6 s =
  let elts = [s.[0]; s.[1]; s.[2]; s.[3];
	      s.[4]; s.[5]; s.[6]; s.[7];
	      s.[8]; s.[9]; s.[10]; s.[11];
	      s.[12]; s.[13]; s.[14]; s.[15]] in
  VRecord [ 
    "@name", VString ("ipv6", false);
    "@string_of", VString (string_of_ipv6 s, false);
    "address", VList (List.map (fun x -> VSimpleInt (int_of_char x)) elts)
  ]


(* Magic *)

type magic = string

let parse_magic magic_expected input =
  let s = parse_string (String.length magic_expected) input in
  if s = magic_expected then s
  else raise (ParsingException (CustomException ("invalid magic (\"" ^
				  (hexdump s) ^ "\")"), _h_of_si input))

let lwt_parse_magic magic_expected input =
  lwt_parse_string (String.length magic_expected) input >>= fun s ->
  if s = magic_expected then return s
  else fail (ParsingException (CustomException ("invalid magic (\"" ^
				 (hexdump s) ^ "\")"), _h_of_li input))

let dump_magic buf s = POutput.add_string buf s

let string_of_magic s = hexdump s

let value_of_magic s = VString (s, true)


(* Null Terminated Strings *)

(* nt_string(len) reads a string(len) unless a null character arises, *)
(* then it checks the remaining characters are null ones.             *)

type nt_string = string

let parse_nt_string len input =
  let saved_offset = input.cur_offset in
  let s = parse_string len input in
  try
    let index = String.index s '\x00' in

    if String.sub s index (len - index) <> String.make (len - index) '\x00'
    then emit_parsing_exception false (CustomException "Unclean Null Terminated String")
      { input with cur_offset = saved_offset };

    String.sub s 0 index;
  with Not_found -> s

let dump_nt_string len buf s =
  let missing_len = len - (String.length s) in
  POutput.add_string buf s;
  POutput.add_string buf (String.make missing_len '\x00')

let value_of_nt_string s = VString (s, false)


(* cstring reads a string until a null character arises *)

type cstring = string

let parse_cstring input =
  let res = Buffer.create 1024 in
  let rec aux buf input =
    let next_char = parse_uint8 input in
    if next_char <> 0
    then begin
      Buffer.add_char buf (char_of_int next_char);
      aux buf input
    end
  in
  aux res input;
  Buffer.contents res

let dump_cstring buf s =
  POutput.add_string buf s;
  POutput.add_char buf '\x00'

let value_of_cstring s = VString (s, false)




(* Containers *)

type length_constraint =
  | NoConstraint
  | AtLeast of int
  | AtMost of int
  | Exactly of int
  | Between of int * int

let handle_length_constraint input len = function
  | NoConstraint -> ()
  | AtLeast n ->
    if len < n then raise (ParsingException (TooFewObjects (len, n), _h_of_si input))
  | AtMost n ->
    if len > n then raise (ParsingException (TooManyObjects (len, n), _h_of_si input))
  | Exactly n ->
    if len < n then raise (ParsingException (TooFewObjects (len, n), _h_of_si input));
    if len > n then raise (ParsingException (TooManyObjects (len, n), _h_of_si input))
  | Between (n1, n2) ->
    if len < n1 then raise (ParsingException (TooFewObjects (len, n1), _h_of_si input));
    if len > n2 then raise (ParsingException (TooManyObjects (len, n2), _h_of_si input))


type 'a length_constrained_container = 'a

let parse_length_constrained_container len_cons _name parse_fun input =
  let old_offset = input.cur_offset in
  let content = parse_fun input in
  let len = input.cur_offset - old_offset in
  handle_length_constraint input len len_cons;
  content

let dump_length_constrained_container (* len_cons *) dump_fun buf o =
  (* Warning if length constraint not validated? *)
  dump_fun buf o

let value_of_length_constrained_container = value_of_container


type 'a enrich_blocker = 'a

let parse_enrich_blocker level _name parse_fun input =
  let enrich_value = if level > 1 then EnrichLevel level else NeverEnrich in
  let new_input = { input with enrich = enrich_value } in
  let res = parse_fun new_input in
  input.cur_offset <- new_input.cur_offset;
  res

let dump_enrich_blocker dump_fun buf o = dump_fun buf o

let value_of_enrich_blocker = value_of_container



type 'a hex_container = 'a

let reverse_hex_chars =
  [|-1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1;
    -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1;
    -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1;
     0;  1;  2;  3;  4;  5;  6;  7;  8;  9; -1; -1; -1; -1; -1; -1;
    -1; 10; 11; 12; 13; 14; 15; -1; -1; -1; -1; -1; -1; -1; -1; -1;
    -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1;
    -1; 10; 11; 12; 13; 14; 15; -1; -1; -1; -1; -1; -1; -1; -1; -1;
    -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1;
    -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1;
    -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1;
    -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1;
    -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1;
    -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1;
    -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1;
    -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1;
    -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1; -1|]

let extract_4bits input =
  let c = parse_byte input in
  match reverse_hex_chars.(c) with
  | -1 -> raise (ParsingException (InvalidHexString "invalid character", _h_of_si input))
  | res -> res

let hexparse input =
  let len = input.cur_length - input.cur_offset in
  if len mod 2 <> 0 then raise (ParsingException (InvalidHexString "odd-length string", _h_of_si input));
  let res = String.make (len / 2) ' ' in
  for i = 0 to (len / 2) - 1 do
    let hibits = extract_4bits input in
    let lobits = extract_4bits input in
    res.[i] <- char_of_int ((hibits lsl 4) lor lobits)
  done;
  res

let parse_hex_container name parse_fun input =
  let content = hexparse input in
  let new_input = get_in_container input name content in
  let res = parse_fun new_input in
  check_empty_input true new_input;
  res


let lwt_extract_4bits input =
  let handle_exn = function
    | ParsingException (OutOfBounds, _) -> return None
    | e -> fail e
  in
  let parsing_thread () =
    lwt_parse_byte input >>= fun c ->
    match reverse_hex_chars.(c) with
    | -1 -> raise (ParsingException (InvalidHexString "invalid character", _h_of_li input))
    | res -> return (Some res)
  in
  try_bind parsing_thread return handle_exn

let lwt_hexparse input =
  let rec lwt_hexparse_aux buf input =
    lwt_extract_4bits input >>= function
    | None -> return ()
    | Some hibits ->
      lwt_extract_4bits input >>= function
      | None -> fail (ParsingException (InvalidHexString "odd-length string", _h_of_li input))
      | Some lobits ->
	POutput.add_byte buf ((hibits lsl 4) lor lobits);
	lwt_hexparse_aux buf input
  in
  let buf = POutput.create () in
  lwt_hexparse_aux buf input >>= fun () ->
  return (POutput.contents buf)

let lwt_parse_hex_container name parse_fun input =
  lwt_hexparse input >>= fun content ->
  let new_input = lwt_get_in_container input name content in
  let res = parse_fun new_input in
  check_empty_input true new_input;
  return res


let dump_hex_container dump_fun buf o =
  let tmp_buf = POutput.create () in
  dump_fun tmp_buf o;
  POutput.add_string buf (hexdump (POutput.contents tmp_buf))

let value_of_hex_container = value_of_container



(* Safe union handling *)

type 'a safe_union = 'a
let parse_safe_union discriminator fallback_discriminator _name parse_fun input =
  match try_parse (parse_fun discriminator) input with
  | None -> parse_fun fallback_discriminator input
  | Some res -> res
(* TODO: lwt_parse_safe_union would need a lwt_subtype to be set by our code
   For now, it is impossible to do so because only code in parsifalSyntax has access to this *)
let dump_safe_union dump_fun buf u = dump_fun buf u
let value_of_safe_union = value_of_container


type 'a exact_safe_union = 'a
let parse_exact_safe_union discriminator fallback_discriminator _name parse_fun input =
  match try_parse ~exact:true (parse_fun discriminator) input with
  | None -> parse_fun fallback_discriminator input
  | Some res -> res
(* TODO: lwt_parse_exact_safe_union *)
let dump_exact_safe_union dump_fun buf u = dump_fun buf u
let value_of_exact_safe_union = value_of_container


type 'a safe_asn1_union = 'a
let parse_safe_asn1_union _name parse_fun input =
  match try_parse parse_fun input with
  | Some res -> res
  | None ->
    let new_input = { input with enrich = NeverEnrich } in
    let res = parse_fun new_input in
    input.cur_offset <- new_input.cur_offset;
    res
let dump_safe_asn1_union dump_fun buf u = dump_fun buf u
let value_of_safe_asn1_union = value_of_container


type 'a conditional_container = 'a option
let parse_conditional_container condition _name parse_fun input =
  if condition
  then Some (parse_fun input)
  else None
let dump_conditional_container dump_fun buf o = try_dump dump_fun buf o
let value_of_conditional_container value_of_fun o = try_value_of value_of_fun o

type 'a trivial_union = Parsed of 'a | Unparsed of binstring
let parse_trivial_union condition _name parse_fun input =
  if should_enrich condition input.enrich
  then Parsed (parse_fun input)
  else Unparsed (parse_rem_binstring input)
let dump_trivial_union dump_fun buf = function
  | Parsed x -> dump_fun buf x
  | Unparsed s -> POutput.add_string buf s
let value_of_trivial_union value_of_fun = function
  | Parsed x -> value_of_fun x
  | Unparsed s -> VUnparsed (VString (s, true))


(* Parse checkpoints and raw values *)

let parse_save_offset input = input.cur_offset
let lwt_parse_save_offset input = input.lwt_offset
let parse_seek_offset offset input = input.cur_offset <- offset
let lwt_parse_seek_offset offset input =
  let handle_unix_error = function
    | Unix.Unix_error (Unix.ESPIPE, "lseek", "") -> return ()
    | e -> fail e
  and set_offset () =
    Lwt_io.set_position input.lwt_ch (Int64.of_int offset) >>= fun _ ->
    (* TODO: Warning, integer overflow is possible! *)
      input.lwt_offset <- offset;
      return ()
  in try_bind (set_offset) (fun () -> return ()) handle_unix_error

let parse_seek_offsetrel offset input = input.cur_offset <- (input.cur_offset + offset)
let lwt_parse_seek_offsetrel offset input =
  let handle_unix_error = function
    | Unix.Unix_error (Unix.ESPIPE, "lseek", "") -> return ()
    | e -> fail e
  and set_offset () =
    let new_offset = Int64.add (Int64.of_int input.lwt_offset) (Int64.of_int offset) in
    Lwt_io.set_position input.lwt_ch new_offset >>= fun _ ->
    (* TODO: Warning, integer overflow is possible! *)
      input.lwt_offset <- (input.lwt_offset + offset);
      return ()
  in try_bind (set_offset) (fun () -> return ()) handle_unix_error


type raw_value = string option
let parse_raw_value offset input =
  Some (String.sub input.str (input.cur_base + offset) (input.cur_offset - offset))
let lwt_parse_raw_value _offset input =
  fail (ParsingException (NotImplemented "lwt_parse_raw_value", _h_of_li input))

let value_of_raw_value = function
  | None -> VUnit
  | Some s -> VString (s, true)


(* Ignore trailing bytes *)
let parse_ignore = drop_rem_bytes


(* ParsingStop raiser on condition *)
let parse_stop_if condition _input =
  if condition then raise ParsingStop
