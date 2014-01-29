open Lwt

(***********)
(* Options *)
(***********)

let default_buffer_size = ref 1024


(*********************)
(* Trivial functions *)
(*********************)

let const s _ = s
let id x = x

let pop_opt default = function
  | None -> default
  | Some x -> x

let hash_get ht k default =
  try Hashtbl.find ht k
  with Not_found -> default


let hexa_char = "0123456789abcdef"

let hexdump s =
  let len = String.length s in
  let res = String.make (len * 2) ' ' in
  for i = 0 to (len - 1) do
    let x = int_of_char (String.get s i) in
    res.[i * 2] <- hexa_char.[(x lsr 4) land 0xf];
    res.[i * 2 + 1] <- hexa_char.[x land 0xf];
  done;
  res


let string_split c s =
  let rec aux offset =
    try
      let next_index = String.index_from s offset c in
      (String.sub s offset (next_index - offset))::(aux (next_index + 1))
    with Not_found ->
      let len = String.length s in
      if offset < len then [String.sub s offset (len - offset)] else []
  in aux 0


let quote_string s =
  let n = String.length s in

  let estimate_len_char c =
    match c with
      | '\n' | '\t' | '\\' | '"' -> 2
      | c -> let x = int_of_char c in
	     if x >= 32 && x < 128 then 1 else 4
  in
  let rec estimate_len accu offset =
    if offset = n then accu
    else estimate_len (accu + estimate_len_char (s.[offset])) (offset + 1)
  in

  let newlen = estimate_len 2 0 in
  let res = String.make newlen '"' in

  let mk_two_char c offset =
    res.[offset] <- '\\';
    res.[offset + 1] <- c;
    offset + 2
  in
  let write_char c offset =
    match c with
      | '\n' -> mk_two_char 'n' offset
      | '\t' -> mk_two_char 't' offset
      | '\\' -> mk_two_char '\\' offset
      | '"' -> mk_two_char '"' offset
      | c ->
	let x = int_of_char c in
	if x >= 32 && x < 128
	then begin
	  res.[offset] <- c;
	  offset + 1
	end else begin
	  res.[offset] <- '\\';
	  res.[offset + 1] <- 'x';
	  res.[offset + 2] <- hexa_char.[x lsr 4];
	  res.[offset + 3] <- hexa_char.[x land 15];
	  offset + 4
	end
  in
  let rec write_string src_offset dst_offset =
    if src_offset < n then begin
      let new_offset = write_char s.[src_offset] dst_offset in
      write_string (src_offset + 1) (new_offset)
    end
  in
  write_string 0 1;
  res


let mapi f l =
  let rec mapi_aux f accu i = function
    | [] -> List.rev accu
    | x::xs -> mapi_aux f ((f i x)::accu) (i+1) xs
  in mapi_aux f [] 0 l


(***************)
(* value types *)
(***************)

(* TODO: value_of should be used when efficiency is not needed *)
(*       -> string_of, json_of                                 *)

type size = int
type endianness = LittleEndian | BigEndian
(* type header = string *)

type value =
  | VUnit
  | VBool of bool
  | VSimpleInt of int
  | VInt of int * size * endianness
  | VBigInt of string * endianness
  | VEnum of string * int * size * endianness
  | VString of string * bool (* * header *)
  | VList of value list (* * header *)
  | VRecord of (string * value) list
  | VOption of value option
  | VError of string
  | VLazy of value Lazy.t
  | VUnparsed of value



(**********************)
(* Parsing structures *)
(**********************)

(* String and Lwt input definitions *)

type history = (string * int * int option) list

type enrich_style =
  | AlwaysEnrich
  | EnrichLevel of int
  | DefaultEnrich
  | NeverEnrich

let update_enrich = function
  | EnrichLevel n ->
    if n <= 1
    then NeverEnrich
    else EnrichLevel (n-1)
  | (AlwaysEnrich | DefaultEnrich | NeverEnrich) as e -> e

type bitstate =
  | NoBitState
  | LeftToRight of int * int
  | RightToLeft of int * int

type string_input = {
  str : string;
  cur_name : string;
  cur_base : int;
  mutable cur_offset : int;
  mutable cur_bitstate : bitstate;
  cur_length : int;
  enrich : enrich_style;
  history : history;
  err_fun : string -> unit
}

type lwt_input = {
  lwt_ch : Lwt_io.input_channel;
  lwt_name : string;
  mutable lwt_offset : int;
  mutable lwt_bitstate : bitstate;
  lwt_rewindable : bool;
  mutable lwt_length : int;
  lwt_enrich : enrich_style;
  lwt_err_fun : string -> unit
}

let print_history ?prefix:(prefix=" in ") history =
  let print_elt = function
    | (n, o, None)   -> Printf.sprintf "%s (%d/?)" n o
    | (n, o, Some l) -> Printf.sprintf "%s (%d/%d)" n o l
  in
  let aux h = String.concat ", " (List.map print_elt h) in
  match history with
    | [] -> ""
    | e::h -> Printf.sprintf "%s%s [%s]" prefix (print_elt e) (aux h)


type parsing_exception =
  | OutOfBounds
  | UnexpectedTrailingBytes
  | EmptyHistory
  | NonEmptyHistory
  | UnableToRewind
  | InvalidBase64String of string
  | InvalidHexString of string
  | CustomException of string
  | ValueNotInEnum of string * int
  | NotImplemented of string
  | TooFewObjects of int * int
  | TooManyObjects of int * int

let print_parsing_exception = function
  | OutOfBounds -> "OutOfBounds"
  | UnexpectedTrailingBytes -> "UnexpectedTrailingBytes"
  | EmptyHistory -> "EmptyHistory"
  | NonEmptyHistory -> "NonEmptyHistory"
  | UnableToRewind -> "UnableToRewind"
  | InvalidBase64String e -> "Invalid base64 string (" ^ e ^ ")"
  | InvalidHexString e -> "Invalid hex string (" ^ e ^ ")"
  | CustomException e -> e
  | ValueNotInEnum (e, x) ->
    Printf.sprintf "Invalid %s (%d)" e x
  | NotImplemented feat -> "Not implemented (" ^ feat ^ ")"
  | TooFewObjects (x, exp_x) ->
    Printf.sprintf "Too few objects (%d instead of %d)" x exp_x
  | TooManyObjects (x, exp_x) ->
    Printf.sprintf "Too many objects (%d instead of %d)" x exp_x

exception ParsingException of parsing_exception * history
exception ParsingStop

let value_not_in_enum s x h = raise (ParsingException (ValueNotInEnum (String.copy s, x), h))

let not_implemented s = raise (ParsingException (NotImplemented (String.copy s), []))
let lwt_not_implemented s = fail (ParsingException (NotImplemented (String.copy s), []))

let string_of_exception e h = (print_parsing_exception e) ^ (print_history h)

let _h_of_si i = (i.cur_name, i.cur_offset, Some i.cur_length)::i.history
let _h_of_li i = [i.lwt_name, i.lwt_offset, None]

let emit_parsing_exception fatal e i =
  let h = _h_of_si i in
  if fatal
  then raise (ParsingException (e, h))
  else i.err_fun (string_of_exception e h)

let lwt_emit_parsing_exception fatal e i =
  let h = _h_of_li i in
  if fatal
  then fail (ParsingException (e, h))
  else return (i.lwt_err_fun (string_of_exception e h))



(* string_input manipulation *)

let input_of_string ?verbose:(verbose=true) ?enrich:(enrich=DefaultEnrich) name s = {
    str = s;
    cur_name = name;
    cur_base = 0;
    cur_offset = 0;
    cur_bitstate = NoBitState;
    cur_length = String.length s;
    enrich = enrich;
    history = [];
    err_fun = if verbose then prerr_endline else ignore
  }

let get_in input name len =
  let new_history = _h_of_si input in
  if len < 0 then raise (ParsingException (OutOfBounds, new_history)) ;
  if input.cur_offset + len <= input.cur_length
  then {
    str = input.str;
    cur_name = name;
    cur_base = input.cur_base + input.cur_offset;
    cur_offset = 0;
    cur_bitstate = NoBitState;
    cur_length = len;
    enrich = update_enrich input.enrich;
    history = new_history;
    err_fun = input.err_fun
  } else raise (ParsingException (OutOfBounds, new_history))

let get_in_container input name s =
  let new_history = _h_of_si input in
  { str = s;
    cur_name = name;
    cur_base = 0;
    cur_offset = 0;
    cur_bitstate = NoBitState;
    cur_length = String.length s;
    enrich = update_enrich input.enrich;
    history = new_history;
    err_fun = input.err_fun
  }

let get_out old_input input =
  if (input.cur_offset < input.cur_length) || (input.cur_bitstate <> NoBitState)
  then raise (ParsingException (UnexpectedTrailingBytes, _h_of_si input))
  else old_input.cur_offset <- old_input.cur_offset + input.cur_length


let append_to_input input next_string =
  if input.cur_base = 0 && input.cur_bitstate = NoBitState && input.history = []
  then begin
    let new_str = (String.sub input.str input.cur_offset (input.cur_length - input.cur_offset)) ^ next_string in
    { input with
      str = new_str;
      cur_offset = 0;
      cur_length = String.length new_str
    }
  end else { input with
    str = input.str ^ next_string;
    cur_length = input.cur_length + (String.length next_string);
  }

let drop_used_string input =
  if input.cur_base = 0 && input.cur_bitstate = NoBitState && input.history = []
  then begin
    let new_str = String.sub input.str input.cur_offset (input.cur_length - input.cur_offset) in
    { input with
      str = new_str;
      cur_offset = 0;
      cur_length = String.length new_str
    }
  end else raise (ParsingException (NonEmptyHistory, _h_of_si input))


let eos input =
  input.cur_offset >= input.cur_length && input.cur_bitstate = NoBitState

let check_empty_input fatal input =
  if not (eos input) then emit_parsing_exception fatal UnexpectedTrailingBytes input

let try_parse ?exact:(exact=false) ?report:(report=false) parse_fun input =
  if eos input then None else begin
    let saved_offset = input.cur_offset
    and saved_bitstate = input.cur_bitstate in
    try
      let res = Some (parse_fun input) in
      if exact then check_empty_input true input;
      res
    with ParsingException (e, h) ->
      if report then input.err_fun (string_of_exception e h);
      input.cur_offset <- saved_offset;
      input.cur_bitstate <- saved_bitstate;
      None
  end

let exact_parse parse_fun input =
  let res = parse_fun input in
  check_empty_input true input;
  res



(* lwt_input manipulation *)

let channel_length ch =
  let handle_unix_error = function
    | Unix.Unix_error (Unix.ESPIPE, "lseek", "") -> return None
    | e -> fail e
  and get_length () = Lwt_io.length ch
  and is_not_null x = return (Some (Int64.to_int x))  (* TODO: Warning, integer overflow is possible! *)
  in try_bind get_length is_not_null handle_unix_error

let input_of_channel ?verbose:(verbose=true) ?enrich:(enrich=DefaultEnrich) name ch =
  channel_length ch >>= fun l ->
  let rewindable, length = match l with
    | None -> false, 0
    | Some len -> true, len
  in
  return { lwt_ch = ch; lwt_name = name;
	   lwt_offset = Int64.to_int (Lwt_io.position ch);
	   (* TODO: Possible integer overflow in 32-bit *)
	   lwt_bitstate = NoBitState;
	   lwt_rewindable = rewindable;
	   lwt_length = length;
	   lwt_enrich = enrich;
           lwt_err_fun = if verbose then prerr_endline else ignore }

let input_of_fd ?verbose:(verbose=true) ?enrich:(enrich=DefaultEnrich) name fd =
  let ch = Lwt_io.of_fd Lwt_io.input fd in
  input_of_channel ~verbose:verbose ~enrich:enrich name ch

let input_of_filename ?verbose:(verbose=true) ?enrich:(enrich=DefaultEnrich) filename =
  Lwt_unix.openfile filename [Unix.O_RDONLY] 0 >>= fun fd ->
  input_of_fd ~verbose:verbose ~enrich:enrich filename fd


let lwt_really_read input len =
  let buf = String.make len ' ' in
  let _really_read () = Lwt_io.read_into_exactly input.lwt_ch buf 0 len
  and finalize_ok () =
    input.lwt_offset <- input.lwt_offset + len;
    return buf
  and finalize_nok = function
    | End_of_file -> fail (ParsingException (OutOfBounds, _h_of_li input))
    | e -> fail e
  in try_bind _really_read finalize_ok finalize_nok

let lwt_really_read_no_update input len =
  let buf = String.make len ' ' in
  let _really_read () = Lwt_io.read_into_exactly input.lwt_ch buf 0 len
  and finalize_ok () = return buf
  and finalize_nok = function
    | End_of_file -> fail (ParsingException (OutOfBounds, _h_of_li input))
    | e -> fail e
  in try_bind _really_read finalize_ok finalize_nok

let lwt_get_in input name len =
  let new_history = [input.lwt_name, input.lwt_offset, None] in
  if len < 0 then raise (ParsingException (OutOfBounds, new_history)) ;
  lwt_really_read_no_update input len >>= fun s ->
  return {
    str = s;
    cur_name = name;
    cur_base = 0;
    cur_offset = 0;
    cur_bitstate = NoBitState;
    cur_length = len;
    enrich = update_enrich input.lwt_enrich;
    history = new_history;
    err_fun = input.lwt_err_fun
  }

let lwt_get_in_container input name s =
  let new_history = _h_of_li input in
  { str = s;
    cur_name = name;
    cur_base = 0;
    cur_offset = 0;
    cur_bitstate = NoBitState;
    cur_length = String.length s;
    enrich = update_enrich input.lwt_enrich;
    history = new_history;
    err_fun = input.lwt_err_fun
  }

let lwt_get_out old_input input =
  if (input.cur_offset < input.cur_length) || (input.cur_bitstate <> NoBitState)
  then fail (ParsingException (UnexpectedTrailingBytes, _h_of_si input))
  else begin
    old_input.lwt_offset <- old_input.lwt_offset + input.cur_length;
    return ()
  end

let lwt_eos input =
  input.lwt_rewindable && (input.lwt_offset >= input.lwt_length) && (input.lwt_bitstate = NoBitState)

let lwt_check_empty_input fatal input =
  if lwt_eos input
  then return ()
  else lwt_emit_parsing_exception fatal UnexpectedTrailingBytes input


let lwt_try_parse lwt_parse_fun input =
  if lwt_eos input then return None else begin
    let saved_offset = input.lwt_offset
    and saved_bitstate = input.lwt_bitstate in
    let finalize_ok x = return (Some x)
    and finalize_nok = function
      | ParsingException _ ->
	input.lwt_offset <- saved_offset;
	input.lwt_bitstate <- saved_bitstate;
	if input.lwt_rewindable
	then begin
	  Lwt_io.set_position input.lwt_ch (Int64.of_int saved_offset) >>= fun () ->
	  return None
	end else fail (ParsingException (UnableToRewind, _h_of_li input))
      | e -> fail e
    in try_bind (fun () -> lwt_parse_fun input) finalize_ok finalize_nok
  end

let lwt_exact_parse lwt_parse_fun input =
  lwt_parse_fun input >>= fun res ->
  lwt_check_empty_input true input >>= fun () ->
  return res


(************************)
(* Construction helpers *)
(************************)

(* Enums *)

let print_enum string_of_val int_of_val nchars ?indent:(indent="") ?name:(name="enum") v =
  Printf.sprintf "%s%s: %s (0x%*.*x)\n" indent name (string_of_val v) nchars nchars (int_of_val v)

let value_of_enum string_of_val int_of_val size endianness v =
  VEnum (string_of_val v, int_of_val v, size, endianness)


(* Struct *)

let try_dump dump_fun buf = function
  | None -> ()
  | Some x -> dump_fun buf x

let try_value_of (value_of_fun : 'a -> value) = function
  | None -> VUnit
  | Some x -> value_of_fun x



(* Unions *)

let should_enrich global_ref local_arg =
  match !global_ref, local_arg with
  | true, DefaultEnrich -> true
  | _, (AlwaysEnrich | EnrichLevel _) -> true
  | _, (DefaultEnrich | NeverEnrich) -> false



(*******************)
(* Parsing helpers *)
(*******************)

let parse_byte input =
  if input.cur_offset < input.cur_length then begin
    let res = int_of_char (input.str.[input.cur_base + input.cur_offset]) in
    input.cur_offset <- input.cur_offset + 1;
    res
  end else raise (ParsingException (OutOfBounds, _h_of_si input))

let lwt_parse_byte input =
  lwt_really_read input 1 >>= fun s ->
  return (int_of_char (s.[0]))


let rec drop_while predicate input =
  let c = parse_byte input in
  if predicate c
  then drop_while predicate input
  else c

let rec _read_while b predicate input =
  let c = parse_byte input in
  if predicate c then begin
    Buffer.add_char b (char_of_int c);
    _read_while b predicate input
  end

let read_while predicate input =
  let b = Buffer.create 32 in
  _read_while b predicate input;
  Buffer.contents b


let rec lwt_drop_while predicate input =
  lwt_parse_byte input >>= fun c ->
  if predicate c
  then lwt_drop_while predicate input
  else return c

let rec _lwt_read_while b predicate input =
  lwt_parse_byte input >>= fun c ->
  if predicate c then begin
    Buffer.add_char b (char_of_int c);
    _lwt_read_while b predicate input
  end else return ()

let lwt_read_while predicate input =
  let b = Buffer.create 32 in
  _lwt_read_while b predicate input >>= fun () ->
  return (Buffer.contents b)


let parse_both_equal fatal err a b input =
  if a <> b
  then emit_parsing_exception fatal err input


(* Bit handling *)
(* TODO: We do NOT check for integer overflow! *)

(* LeftToRight reading *)
let _bits_masks = [|0; 1; 3; 7; 15; 31; 63; 127; 255|]
let parse_bits nbits input =
  let rec parse_bits_aux nbits cur_byte remaining_bits input res =
    match nbits, remaining_bits with
    | 0, _ -> (cur_byte, remaining_bits), res
    | _, 0 -> parse_bits_aux nbits (parse_byte input) 8 input res
    | _, _ ->
      if nbits <= remaining_bits
      then begin
	let new_rem = remaining_bits - nbits in
	let new_state = cur_byte, new_rem
	and new_res = (res lsl nbits) lor ((cur_byte lsr new_rem) land _bits_masks.(nbits))
	in new_state, new_res
      end else begin
	let new_res = (res lsl remaining_bits) lor (cur_byte land _bits_masks.(remaining_bits)) in
	parse_bits_aux (nbits - remaining_bits) (parse_byte input) 8 input new_res
      end
  in
  let cur_byte, remaining_bits = match input.cur_bitstate with
    | NoBitState -> 0, 0
    | LeftToRight (b, nbits) -> b, nbits
    | RightToLeft _ -> raise (ParsingException (CustomException "Inconsistant bit state (RtoL or LtoR ?)", _h_of_si input))
  in
  let (b, rem_bits), res = parse_bits_aux nbits cur_byte remaining_bits input 0 in
  input.cur_bitstate <- (if rem_bits = 0 then NoBitState else LeftToRight (b, rem_bits));
  res

let lwt_parse_bits nbits input =
  let rec lwt_parse_bits_aux nbits cur_byte remaining_bits input res =
    match nbits, remaining_bits with
    | 0, _ -> return ((cur_byte, remaining_bits), res)
    | _, 0 ->
      lwt_parse_byte input >>= fun b ->
      lwt_parse_bits_aux nbits b 8 input res
    | _, _ ->
      if nbits <= remaining_bits
      then begin
	let new_rem = remaining_bits - nbits in
	let new_state = cur_byte, new_rem
	and new_res = (res lsl nbits) lor ((cur_byte lsr new_rem) land _bits_masks.(nbits))
	in return (new_state, new_res)
      end else begin
	let new_res = (res lsl remaining_bits) lor (cur_byte land _bits_masks.(remaining_bits)) in
	lwt_parse_byte input >>= fun b ->
	lwt_parse_bits_aux (nbits - remaining_bits) b 8 input new_res
      end
  in
  let cur_byte, remaining_bits = match input.lwt_bitstate with
    | NoBitState -> 0, 0
    | LeftToRight (b, nbits) -> b, nbits
    | RightToLeft _ -> raise (ParsingException (CustomException "Inconsistant bit state (RtoL or LtoR ?)", _h_of_li input))
  in
  lwt_parse_bits_aux nbits cur_byte remaining_bits input 0 >>= fun ((b, rem_bits), res) ->
  input.lwt_bitstate <- (if rem_bits = 0 then NoBitState else LeftToRight (b, rem_bits));
  return res

(* RightToLeft reading *)
let parse_rtol_bit input =
  let new_bitstate, res = match input.cur_bitstate with
    | NoBitState ->
      let b = parse_byte input in
      RightToLeft (b lsr 1, 7), (b land 1)
    | RightToLeft (b, 1) -> NoBitState, (b land 1)
    | RightToLeft (b, nbits) -> RightToLeft (b lsr 1, nbits - 1), (b land 1)
    | LeftToRight _ -> raise (ParsingException (CustomException "Inconsistant bit state (RtoL or LtoR ?)", _h_of_si input))
  in
  input.cur_bitstate <- new_bitstate;
  res

(* This may seem like pure madness, but zLib/PNG (RFCs 1950/1951) work exactly
   like that: if a byte contains two 4-bit values, A..a followed by B..b,
   where the uppercase bit is the MSB, and the lowercase bit is the LSB, the
   bits are ordered as follows:

          7  4 3  0
         +---------+
         |B..b|A..a|
         +---------+
*)
(* TODO: Improve this version that may be more efficient *)
let parse_rtol_bits nbits input =
  let rec parse_rtol_bits_aux input = function
    | 0 -> 0
    | nbits ->
      let b = parse_rtol_bit input in
      b lor ((parse_rtol_bits_aux input (nbits - 1)) lsl 1)
  in parse_rtol_bits_aux input nbits



let drop_remaining_bits input =
  input.cur_bitstate <- NoBitState



(*******************)
(* Dumping helpers *)
(*******************)

let exact_dump dump_fun x =
  let res = POutput.create () in
  dump_fun res x;
  POutput.contents res


(********************)
(* Value of helpers *)
(********************)

type ('a, 'b) either = Left of 'a | Right of 'b

let rec string_of_value = function
  | VUnit -> "()"
  | VBool b -> string_of_bool b
  | VSimpleInt i | VInt (i, _, _) -> string_of_int i
  | VBigInt (s, _) | VString (s, true) -> hexdump s
  | VString (s, false) -> quote_string s
  | VEnum (s, _, _, _) -> s
  | VList _ -> "list"
  | VRecord l -> begin
    try string_of_value (List.assoc "@string_of" l)
    with Not_found -> begin
      try string_of_value (List.assoc "@name" l)
      with Not_found -> "record"
    end
  end
  | VOption None -> "()"
  | VOption (Some v) -> string_of_value v
  | VError s -> "Error: " ^ s
  | VLazy v -> string_of_value (Lazy.force v)
  | VUnparsed v -> "[Unparsed]_" ^ string_of_value v


let rec realise_value = function
  | VLazy v -> realise_value (Lazy.force v)
  | v -> v

let cleanup_result init l =
  let _cleanup_result accu next = match accu, next with
    | Left _, VError _ -> accu
    | Left _, v -> Right [v]
    | Right [], VError _ -> Left next
    | Right vs, VError _ -> Right vs
    | Right vs, v -> Right (v::vs)
  in
  match List.fold_left _cleanup_result init l with
  | Left verr -> verr
  | Right vs -> VList (List.rev vs)

let list_of_fields l =
  let add_field accu (n, v) =
    if String.length n > 1 && n.[0] <> '@'
    then v::accu
    else accu
  in
  List.rev (List.fold_left add_field [] l)


let rec print_value ?maxlen:(maxlen=Some 70) ?verbose:(verbose=false) ?indent:(indent="") ?name:(name="value") = function
  | VUnit ->  Printf.sprintf "%s%s\n" indent name
  | VBool b -> Printf.sprintf "%s%s: %b\n" indent name b
  | VSimpleInt i -> Printf.sprintf "%s%s: %d\n" indent name i
  | VInt (i, sz, _) ->
    let n_chars = sz / 4 in
    Printf.sprintf "%s%s: %d (0x%*.*x)\n" indent name i n_chars n_chars i
  | VBigInt (s, _) ->
    Printf.sprintf "%s%s: %s (%d bytes)\n" indent name (hexdump s) (String.length s)
  | VEnum (s, i, sz, _) -> 
    let n_chars = sz / 4 in
    Printf.sprintf "%s%s: %s (0x%*.*x)\n" indent name s n_chars n_chars i

  | VString ("", _) ->
    Printf.sprintf "%s%s: \"\" (0 byte)\n" indent name
  | VString (s, true) ->
    let real_s = match maxlen with
      | Some l -> if String.length s < l then s else (String.sub s 0 l) ^ ""
      | None -> s
    in
    Printf.sprintf "%s%s: %s (%d bytes)\n" indent name (hexdump real_s) (String.length s)
  | VString (s, false) ->
    let real_s = match maxlen with
      | Some l -> if String.length s < l then s else (String.sub s 0 l) ^ "..."
      | None -> s
    in
    Printf.sprintf "%s%s: %s (%d bytes)\n" indent name (quote_string real_s) (String.length s)

  | VList l ->
    let print_subvalue i x = print_value ~verbose:verbose ~indent:(indent ^ "  ") ~name:(name ^ "[" ^ string_of_int i ^ "]") x in
    (Printf.sprintf "%s%s {\n" indent name) ^
      (String.concat "" (mapi print_subvalue l)) ^
      (Printf.sprintf "%s}\n" indent)
  | VRecord l -> begin
    try
      if verbose
      then raise Not_found
      else Printf.sprintf "%s%s: %s\n" indent name (string_of_value (List.assoc "@string_of" l))
    with Not_found -> begin
      let new_indent = indent ^ "  " in
      let handle_field accu (name, raw_v) = match (name, realise_value raw_v) with
	| _, VUnit -> accu
	| _, VOption None -> accu
	| name, v ->
	  if verbose || (String.length name >= 1 && name.[0] <> '@')
	  then (print_value ~verbose:verbose ~indent:new_indent ~name:name v)::accu
	  else accu
      in
      (Printf.sprintf "%s%s {\n" indent name) ^
	(String.concat "" (List.rev (List.fold_left handle_field [] l))) ^
	(Printf.sprintf "%s}\n" indent)
    end
  end
  | VOption None -> Printf.sprintf "%s%s\n" indent name
  | VOption (Some v) -> print_value ~verbose:verbose ~indent:indent ~name:name v

  | VError err -> Printf.sprintf "%s%s: ERROR (%s)\n" indent name err
  | VLazy v -> print_value ~verbose:verbose ~indent:indent ~name:name (Lazy.force v)
  | VUnparsed v -> print_value ~verbose:verbose ~indent:indent ~name:("[Unparsed]_" ^ name) v


let rec get_value path v = match (realise_value v, path) with
  | v, [] -> v

  (* TODO: add [] pour une chaîne de caractères? *)

  | VSimpleInt i, "@hex"::r ->
    get_value r (VString (Printf.sprintf "0x%x" i, false))
  | VInt (i, sz, _), "@hex"::r ->
    let n_chars = sz / 4 in
    get_value r (VString (Printf.sprintf "0x%*.*x" n_chars n_chars i, false))
  | VEnum (_, i, sz, _), "@hex"::r ->
    let n_chars = sz / 4 in
    get_value r (VString (Printf.sprintf "0x%*.*x" n_chars n_chars i, false))

  | VInt (_, sz, _), ("@len" | "@size")::r -> get_value r (VSimpleInt ((sz + 7) / 8))
  | VBigInt (s, _), ("@len" | "@size")::r -> get_value r (VSimpleInt (String.length s))
  | VEnum (_, _, sz, _), ("@len" | "@size")::r -> get_value r (VSimpleInt ((sz + 7) / 8))

  | VString (s, _), ("@len" | "@size")::r -> get_value r (VSimpleInt (String.length s))


  | VList l, ("@len" | "@size" | "@count")::r -> get_value r (VSimpleInt (List.length l))

  | VList l, "*"::r ->
    cleanup_result (Right []) (List.map (get_value r) l)
  | VList l, "+"::r -> begin
    cleanup_result (Left (VError "Empty list")) (List.map (get_value r) l)
  end
  | VList l, "?"::r -> begin
    match cleanup_result (Right []) (List.map (get_value r) l) with
    | VList (res::_) -> res
    | _ -> VError "Empty list"
  end
  | VList l, "**"::r ->
    let sub_res item = match get_value path item with
      | VList l -> l
      | v -> [v]
    in
    let direct = List.map (get_value r) l
    and indirect = List.flatten (List.map sub_res l) in
    cleanup_result (Right []) (direct@indirect)

  | VList l, p::ps ->
    let len = String.length p in
    if len > 2 && p.[0] = '[' && p.[len - 1] = ']'
    then begin
      try
	let index = int_of_string (String.sub p 1 (len - 2)) in
	get_value ps (List.nth l index)
      with Failure _ -> VError ("Wrong index or index out of bounds (" ^ p ^ ")")
    end else VError ("List index expected (" ^ p ^ ")")


  | VRecord l, "@index"::r ->
    get_value r (VList (List.map (fun (n, _) -> VString (n, false)) l))
  | VRecord l, "@fields"::r ->
    get_value r (VList (list_of_fields l))
  | VRecord l, "@all_fields"::r ->
    get_value r (VList (List.map snd l))

  | VRecord l, ("?" | "+" | "*" | "**")::_ ->
    get_value path (VList (list_of_fields l))

  | VRecord l, field_name::r -> begin
    try get_value r (List.assoc field_name l)
    with Not_found -> VError ("Unknown field (" ^ field_name ^ ")")
  end

  | VError _, _ -> v
  | VLazy v, _ -> get_value path (Lazy.force v)
  | VUnparsed v, _ -> get_value path v

  | _, _ -> VError ("Path not fully interpreted (" ^ (String.concat "." path) ^ ")")



let rec string_of_get_value = function
  | VError e -> Left e
  | VList l ->
    let rec aux error accu l = match error, accu, l with
      | Some e, [], [] -> Left e
      | _, res, [] -> Right ("[" ^ (String.concat ", " (List.rev res)) ^ "]")
      | _, _, v::r ->
	match error, string_of_get_value v with
	| None, Left e -> aux (Some e) accu r
	| _, Left _ -> aux error accu r
	| _, Right s -> aux error (s::accu) r
    in
    aux None [] l
  | v -> Right (string_of_value v)

let get value path_str =
  let path = string_split '.' path_str in
  string_of_get_value (get_value path value)



(* Useful high-level helpers *)
(* TODO: move this code elsewhere? *)

let get_file_content filename =
  let fd = open_in_bin filename in
  try
    let len = in_channel_length fd in
    let res = String.make len '\x00' in
    really_input fd res 0 len;
    close_in fd;
    res
  with e ->
    close_in fd;
    raise e

let string_input_of_filename ?verbose:(verbose=false) ?enrich:(enrich=DefaultEnrich) filename =
  let content = get_file_content filename in
  input_of_string ~verbose:(verbose) ~enrich:(enrich) filename content

let string_input_of_stdin () =
   let input_string = Buffer.create 4096 in
   let buf = String.create 4096 in
   let rec read_more () =
     try
       let n = input stdin buf 0 4096 in
         if n <> 0 then begin
           Buffer.add_substring input_string buf 0 n;
           read_more ()
         end else
           Buffer.contents input_string
     with Sys_error _ -> ""
  in
  input_of_string "(stdin)" (read_more ())

let wrap f () =
  try return (f ())
  with e -> fail e

let wrap1 f x =
  try return (f x)
  with e -> fail e

let wrap2 f x y =
  try return (f x y)
  with e -> fail e
