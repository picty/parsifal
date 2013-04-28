open Parsifal
open BasePTypes
open Lwt


(* IPv4 and IPv6 *)

type ipv4 = string

let parse_ipv4 = parse_string 4
let lwt_parse_ipv4 = lwt_parse_string 4

let dump_ipv4 buf ipv4 = Buffer.add_string buf ipv4

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

let dump_ipv6 buf ipv6 = Buffer.add_string buf ipv6

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

let dump_magic buf s = Buffer.add_string buf s

let string_of_magic s = hexdump s

let value_of_magic s = VString (s, true)


(* Null Terminated Strings *)

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
  Buffer.add_string buf s;
  Buffer.add_string buf (String.make missing_len '\x00')

let value_of_nt_string s = VString (s, false)



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

let parse_length_constrained_container len_cons parse_fun input =
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

let parse_enrich_blocker level parse_fun input =
  let new_input = { input with enrich = EnrichLevel level } in
  let res = parse_fun new_input in
  input.cur_offset <- new_input.cur_offset;
  res

let dump_enrich_blocker dump_fun buf o = dump_fun buf o

let value_of_enrich_blocker = value_of_container


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
