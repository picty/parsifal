(*********)
(* Input *)
(*********)

(* Input interface *)

type input = {
  pop_byte : unit -> int;
  pop_string : int -> string;
  pop_bytes : int -> int list;
  peek_byte : int -> int;
  drop_bytes : int -> unit;
  eos : unit -> bool;

  mk_subinput : int -> input;
}

exception RawOutOfBounds



(* String input *)

let s_pop_byte str offset () =
  try
    let res = str.[!offset] in
    incr offset;
    int_of_char res
  with Invalid_argument _ -> raise RawOutOfBounds

let s_pop_string str offset len =
  try
    let res = String.sub str !offset len in
    offset := !offset + len;
    res
  with Invalid_argument _ -> raise RawOutOfBounds

let s_pop_bytes str offset len =
  let rec aux accu o = function
    | 0 -> List.rev accu
    | n -> aux ((int_of_char str.[o])::accu) (o+1) (n-1)
  in
  try
    let res = aux [] !offset len in
    offset := !offset + len;
    res
  with Invalid_argument _ -> raise RawOutOfBounds

let s_peek_byte str offset off =
  try int_of_char (str.[!offset + off])
  with Invalid_argument _ -> raise RawOutOfBounds

let s_eos n offset () = !offset >= n

let s_drop_bytes str offset n = offset := !offset + n

let rec s_mk_subinput str old_offset local_len =
  let initial_offset = match old_offset with
    | None -> 0
    | Some offset_ref ->
      let tmp = !offset_ref in
      offset_ref := !offset_ref + local_len;
      tmp
  in
  let offset = ref initial_offset in
  { pop_byte = s_pop_byte str offset;
    pop_string = s_pop_string str offset;
    pop_bytes = s_pop_bytes str offset;
    peek_byte = s_peek_byte str offset;
    drop_bytes = s_drop_bytes str offset;
    eos = s_eos (initial_offset + local_len) offset;
    mk_subinput = s_mk_subinput str (Some offset) }

let mk_string_input str = s_mk_subinput str None (String.length str)



(* Stream input *)

let f_pop_byte str () =
  try int_of_char (Stream.next str)
  with Sys_blocked_io | Stream.Failure -> raise RawOutOfBounds

let f_pop_string str len =  
  let res = String.make len ' ' in
  let rec aux o =
    if o < len then begin
      res.[o] <- Stream.next str;
      aux (o+1)
    end else res
  in
  try aux 0 
  with Sys_blocked_io | Stream.Failure -> raise RawOutOfBounds

let f_pop_bytes str len =
  let rec aux accu = function
    | 0 -> List.rev accu
    | n ->
      let next_int = int_of_char (Stream.next str) in
      aux (next_int::accu) (n-1)
  in
  try aux [] len
  with Sys_blocked_io | Invalid_argument _ -> raise RawOutOfBounds

let f_peek_byte str off =
  let l = Stream.npeek (off + 1) str in
  try int_of_char (List.nth l off)
  with Sys_blocked_io | Failure _ -> raise RawOutOfBounds

let f_drop_bytes str off =
  try
    for i = 1 to off do Stream.junk str done
  with Sys_blocked_io | Stream.Failure -> raise RawOutOfBounds

let f_eos str () = Common.eos str

let f_mk_subinput str l =
  let s = f_pop_string str l in
  mk_string_input s

let mk_stream_input str =
  { pop_byte = f_pop_byte str;
    pop_string = f_pop_string str;
    pop_bytes = f_pop_bytes str;
    peek_byte = f_peek_byte str;
    drop_bytes = f_drop_bytes str;
    eos = f_eos str;
    mk_subinput = f_mk_subinput str }




(**************)
(* Severities *)
(**************)

type severity = int

let severities = [| "OK"; "Benign"; "IdempotenceBreaker";
		    "SpecLightlyViolated"; "SpecFatallyViolated";
		    "Fatal" |]
let string_of_severity sev =
  if sev >= 0 && sev < (Array.length severities)
  then severities.(sev)
  else "Wrong severity"

let s_ok = 0
let s_benign = 1
let s_idempotencebreaker = 2
let s_speclightlyviolated = 3
let s_specfatallyviolated = 4
let s_fatal = 5



(*****************)
(* Parsing state *)
(*****************)

type parsing_error = (string * int * string option) (* module name, errno, details *)

type parsing_history = (string * int * int option) list

type parsing_state = {
  ehf : error_handling_function;
  cur_name : string;
  cur_input : input;
  mutable cur_offset : int;
  previous_offset : int;
  cur_length : int option;
  history : parsing_history
}
and error_handling_function = parsing_error -> severity -> parsing_state -> unit

exception OutOfBounds of string
exception ParsingError of parsing_error * severity * parsing_state

let mk_pstate ehf n i o po l h =
  { ehf = ehf; cur_name = n;
    cur_input = i; cur_offset = o;
    previous_offset = po;
    cur_length = l; history = h }

let push_history pstate =
  (pstate.cur_name, pstate.cur_offset, pstate.cur_length)::pstate.history

let string_of_pstate pcontext =
  let string_of_elt (n, o, l) = match l with
    | None -> n ^ "[" ^ (string_of_int o) ^ "]"
    | Some len -> n ^ "[" ^ (string_of_int o) ^ "/" ^ (string_of_int len) ^ "]"
  in
  let positions = List.map string_of_elt (push_history pcontext) in
  "{" ^ (String.concat ", " (List.rev positions)) ^ "}"



(******************)
(* Parsing errors *)
(******************)

type module_error_strings = string array
let error_strings : (string, module_error_strings) Hashtbl.t = Hashtbl.create 10

type 'a assoc_array = ('a * severity * string) array
type 'a emit_fun = 'a -> severity option -> string option -> parsing_state -> unit

let register_module_errors_and_make_emit_function (name : string) (assoc_array : 'a assoc_array) : 'a emit_fun =
  let n = Array.length assoc_array in
  let assoc_hash = Hashtbl.create n in
  let table = Array.make n "" in
  for i = 0 to n - 1 do
    let x, sev, s = assoc_array.(i) in
    Hashtbl.replace assoc_hash x (i, sev);
    table.(i) <- s
  done;
  Hashtbl.replace error_strings name table;

  let emit err sev_opt details pstate =
    let i, sev =
      try
	Hashtbl.find assoc_hash err
      with Not_found -> -1, s_fatal
    in pstate.ehf (name, i, details) (Common.pop_option sev_opt sev) pstate
  in

  emit


let strerror (module_name, errno, details) =
  let main_str =
    try
      let table = Hashtbl.find error_strings module_name in
      table.(errno)
    with _ -> "Unknown error " ^ module_name ^ "." ^ (string_of_int errno)
  in
  match details with
    | None -> main_str
    | Some details_str -> main_str ^ " (" ^ details_str ^ ")"



(******************)
(* Error handling *)
(******************)

let string_of_parsing_error title err sev pstate =
  title ^ " (" ^ (string_of_severity sev) ^ "): " ^
    (strerror err) ^ " inside " ^ (string_of_pstate pstate) ^ "\n"


let default_error_handling_function tolerance minDisplay err sev pstate =
  if sev >= tolerance || sev >= s_fatal
  then raise (ParsingError (err, sev, pstate))
  else if minDisplay <= sev
  then begin
    output_string stderr (string_of_parsing_error "Warning" err sev pstate);
    flush stderr
  end




(*********************)
(* Support Functions *)
(*********************)

let check_bounds pstate to_be_read =
  match pstate.cur_length with
    | None -> true
    | Some len -> pstate.cur_offset + to_be_read <= len

let _pstate_of_stream ehf orig content =
  mk_pstate ehf orig (mk_stream_input content) 0 0 None []

let _pstate_of_string ehf name content =
  mk_pstate ehf (Common.pop_option name "(inline string)") (mk_string_input content)
    0 0 (Some (String.length content)) []




(************************)
(* High-level functions *)
(************************)


(* Generic params *)
let tolerance = ref s_specfatallyviolated
let minDisplay = ref s_ok



let pstate_of_string n s =
  let ehf = default_error_handling_function !tolerance !minDisplay in
  _pstate_of_string ehf n s

let pstate_of_stream n s =
  let ehf = default_error_handling_function !tolerance !minDisplay in
  _pstate_of_stream ehf n s

let pstate_of_channel n s = pstate_of_stream n (Stream.of_channel s)


let go_down pstate name l =
  try
    if not (check_bounds pstate l) then raise RawOutOfBounds;
    let new_input = pstate.cur_input.mk_subinput l in
    let res = mk_pstate pstate.ehf name new_input 0 (pstate.previous_offset + pstate.cur_offset)
      (Some l) (push_history pstate) in
    pstate.cur_offset <- pstate.cur_offset + l;
    res
  with RawOutOfBounds -> raise (OutOfBounds (string_of_pstate pstate))

let go_down_on_left_portion pstate name =
  match pstate.cur_length with
    | None -> raise (OutOfBounds (string_of_pstate pstate))
    | Some l ->
      let left_len = l - pstate.cur_offset in
      go_down pstate name left_len


(* Basic stuff *)

let pop_byte pstate =
  try
    if not (check_bounds pstate 1) then raise RawOutOfBounds;
    let res = pstate.cur_input.pop_byte () in
    pstate.cur_offset <- pstate.cur_offset + 1;
    res
  with RawOutOfBounds -> raise (OutOfBounds (string_of_pstate pstate))

let peek_byte pstate n =
  try
    if not (check_bounds pstate n) then raise RawOutOfBounds;
    pstate.cur_input.peek_byte n
  with RawOutOfBounds -> raise (OutOfBounds (string_of_pstate pstate))

let pop_string pstate =
  try
    match pstate.cur_length with
      | None -> raise RawOutOfBounds
      | Some len ->
	let res = pstate.cur_input.pop_string (len - pstate.cur_offset) in
	pstate.cur_offset <- len;
	res
  with RawOutOfBounds -> raise (OutOfBounds (string_of_pstate pstate))

let pop_string_with_len pstate n =
  try
    if not (check_bounds pstate n) then raise RawOutOfBounds;
    let res = pstate.cur_input.pop_string n in
    pstate.cur_offset <- pstate.cur_offset + n;
    res
  with RawOutOfBounds -> raise (OutOfBounds (string_of_pstate pstate))

let pop_bytes pstate n =
  try
    if not (check_bounds pstate n) then raise RawOutOfBounds;
    let res = pstate.cur_input.pop_bytes n in
    pstate.cur_offset <- pstate.cur_offset + n;
    res
  with RawOutOfBounds -> raise (OutOfBounds (string_of_pstate pstate))

let pop_all_bytes pstate =
  try
    match pstate.cur_length with
      | None -> raise RawOutOfBounds
      | Some len ->
	let res = pstate.cur_input.pop_bytes (len - pstate.cur_offset) in
	pstate.cur_offset <- len;
	res
  with RawOutOfBounds -> raise (OutOfBounds (string_of_pstate pstate))

let drop_bytes pstate n =
  try
    if not (check_bounds pstate n) then raise RawOutOfBounds;
    pstate.cur_input.drop_bytes n;
    pstate.cur_offset <- pstate.cur_offset + n
  with RawOutOfBounds -> raise (OutOfBounds (string_of_pstate pstate))

let eos pstate = pstate.cur_input.eos ()



let rec extract_uint_as_int32_aux accu = function
  | i::r -> extract_uint_as_int32_aux (Int32.logor (Int32.shift_left accu 8) (Int32.of_int i)) r
  | [] -> accu

let extract_uint32_as_int32 pstate = extract_uint_as_int32_aux Int32.zero (pop_bytes pstate 4)


let rec extract_uint_aux accu = function
  | i::r -> extract_uint_aux ((accu lsl 8) lor i) r
  | [] -> accu

let extract_uint32 pstate = extract_uint_aux 0 (pop_bytes pstate 4)
let extract_uint24 pstate = extract_uint_aux 0 (pop_bytes pstate 3)
let extract_uint16 pstate = extract_uint_aux 0 (pop_bytes pstate 2)
let extract_uint8 = pop_byte


(* Strings *)

let extract_string name len pstate =
  let new_pstate = go_down pstate name len in
  pop_string new_pstate

let extract_variable_length_string name length_fun pstate =
  let len = length_fun pstate in
  let new_pstate = go_down pstate name len in
  pop_string new_pstate


(* List of objects *)

let extract_list_fixedlen name len extract_fun pstate =
  let new_pstate = go_down pstate name len in
  let rec aux () =
    if eos new_pstate
    then []
    else begin
      let next = extract_fun new_pstate in
      next::(aux ())
    end
  in
  aux ()

let extract_list name length_fun extract_fun pstate =
  let len = length_fun pstate in
  let new_pstate = go_down pstate name len in
  let rec aux () =
    if eos new_pstate
    then []
    else begin
      let next = extract_fun new_pstate in
      next::(aux ())
    end
  in
  aux ()
