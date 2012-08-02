open Lwt
open Common
open Asn1Enums
open ParsingEngine


let prim_or_cons = function false -> "prim" | true -> "cons"
let print_header = function
  | (C_Universal, false, (T_EndOfContents | T_Boolean | T_Integer | T_BitString | T_OctetString | 
                          T_Null | T_OId | T_ObjectDescriptor | T_External | T_Real | T_Enumerated |
                          T_EmbeddedPDV | T_UTF8String | T_RelativeOId | T_NumericString |
                          T_PrintableString | T_T61String | T_VideoString | T_IA5String |
                          T_UTCTime | T_GeneralizedTime | T_GraphicString | T_VisibleString |
                          T_GeneralString | T_UniversalString | T_UnspecifiedCharacterString |
                          T_BMPString as t)) -> string_of_asn1_tag t

  | (C_Universal, true, (T_Sequence | T_Set as t)) -> string_of_asn1_tag t
  | C_Universal, isC, t -> Printf.sprintf "[UNIV %d] %s" (int_of_asn1_tag t) (prim_or_cons isC)
  | C_Application, isC, t -> Printf.sprintf "[APP %d] %s" (int_of_asn1_tag t) (prim_or_cons isC)
  | C_ContextSpecific, isC, t -> Printf.sprintf "[%d] %s" (int_of_asn1_tag t) (prim_or_cons isC)
  | C_Private, isC, t -> Printf.sprintf "[PRIVATE %d] %s" (int_of_asn1_tag t) (prim_or_cons isC)

type asn1_info = {
  a_offset : int;
  a_hlen : int;
  a_length : int;
  a_class : asn1_class;
  a_isConstructed : bool;
  a_tag : asn1_tag;
}


type asn1_exception =
  | UnexpectedHeader of (asn1_class * bool * asn1_tag) * (asn1_class * bool * asn1_tag) option
  | BooleanNotInNormalForm
  | IntegerNotInNormalForm
  | IntegerOverflow
  | NullNotInNormalForm
  | OIdNotInNormalForm
  | BitStringNotInNormalForm of string
  | InvalidUTCTime
  | UnknownUniversalObject of bool * asn1_tag
  | TooFewObjects of int * int
  | TooManyObjects of int * int

exception Asn1Exception of (asn1_exception * string_input)

let print_asn1_exception = function
  | UnexpectedHeader (h, None) ->
    Printf.sprintf "UnexpectedHeader (%s)" (print_header h)
  | UnexpectedHeader (h, Some exp_h) ->
    Printf.sprintf "UnexpectedHeader (%s instead of %s)" (print_header h) (print_header exp_h)
  | BooleanNotInNormalForm -> "BooleanNotInNormalForm"
  | IntegerNotInNormalForm -> "IntegerNotInNormalForm"
  | IntegerOverflow -> "IntegerOverflow"
  | NullNotInNormalForm -> "NullNotInNormalForm"
  | OIdNotInNormalForm -> "OIdNotInNormalForm"
  | BitStringNotInNormalForm details -> "BitStringNotInNormalForm (" ^ details ^ ")"
  | InvalidUTCTime -> "InvalidUTCTime"
  | UnknownUniversalObject (isC, t) ->
    Printf.sprintf "UnknownUniversalObject (%s)" (print_header (C_Universal, isC, t))
  | TooFewObjects (x, exp_x) ->
    Printf.sprintf "Too few objects (%d instead of %d)" x exp_x
  | TooManyObjects (x, exp_x) ->
    Printf.sprintf "Too many objects (%d instead of %d)" x exp_x


let emit fatal e i =
  if fatal
  then raise (Asn1Exception (e, i))
  else Printf.fprintf stderr "%s in %s\n" (print_asn1_exception e) (print_string_input i)


type expected_header =
  | AH_Simple of (asn1_class * bool * asn1_tag)
  | AH_Complex of (asn1_class -> bool -> asn1_tag -> bool)



(* Header *)

let extract_class (x : int) : asn1_class =
  let i = x lsr 6 in
  asn1_class_of_int i

let extract_isConstructed (x : int) : bool =
  let i = (x lsr 5) land 1 in
  i = 1

let extract_longtype input : asn1_tag  =
  let rec aux accu =
    let byte = parse_uint8 input in
    let new_accu = (accu lsl 7) lor (byte land 0x7f) in
    if (byte land 0x80) = 0
    then new_accu
    else aux new_accu
  in T_Unknown (aux 0)

let extract_header input : (asn1_class * bool * asn1_tag) =
  let hdr = parse_uint8 input in
  let c = extract_class hdr in
  let isC = extract_isConstructed hdr in
  let hdr_t = hdr land 31 in
  let t =
    if (hdr_t < 0x1f)
    then begin
      if c = C_Universal
      then asn1_tag_of_int hdr_t
      else T_Unknown hdr_t
    end else extract_longtype input
  in (c, isC, t)

let extract_length input =
  let first = parse_uint8 input in
  if first land 0x80 = 0
  then first
  else begin
    let accu = ref 0 in
    for i = 1 to (first land 0x7f) do
      accu := (!accu lsl 8) lor (parse_uint8 input);
    done;
    !accu
  end


let check_header header_constraint input c isC t =
  match header_constraint with
    | AH_Simple (exp_c, exp_isC, exp_t) ->
      if c <> exp_c || isC <> exp_isC || t <> exp_t
      then raise (Asn1Exception (UnexpectedHeader ((c, isC, t), Some (exp_c, exp_isC, exp_t)), input))
    | AH_Complex check_fun ->
      if not (check_fun c isC t)
      then raise (Asn1Exception (UnexpectedHeader ((c, isC, t), None), input))

let _extract_asn1_object name header_constraint parse_content input =
  let offset = input.cur_base + input.cur_offset in
  let old_cur_offset = input.cur_offset in
  let c, isC, t = extract_header input in
  check_header header_constraint input c isC t;
  let len = extract_length input in
  let hlen = input.cur_offset - old_cur_offset in
  let new_input = get_in input name len in
  let asn1_info = {
    a_offset = offset;
    a_hlen = hlen;
    a_length = len;
    a_class = c;
    a_isConstructed = isC;
    a_tag = t;
  }
  and raw_string () = String.sub input.str offset (len+hlen) in
  let res = parse_content new_input in
  get_out input new_input;
  res, asn1_info, raw_string

let extract_asn1_object name header_constraint parse_content input =
  let res, _, _ = _extract_asn1_object name header_constraint parse_content input in
  res



let dump_header c isC t =
  let t_int = int_of_asn1_tag t in
  if t_int >= 0x1f then raise (NotImplemented "long type");
  let h = ((int_of_asn1_class c) lsl 6) lor
    (if isC then 0x20 else 0) lor t_int in
  String.make 1 (char_of_int h)

let dump_length l =
  let rec compute_len accu = function
    | 0 -> accu
    | lg -> compute_len (accu + 1) (lg lsr 8)
  in
  let rec aux res i = function
    | 0 -> ()
    | lg ->
      res.[i] <- char_of_int (lg land 0xff);
      aux res (i+1) (lg lsr 8)
  in
  if l < 0x80
  then String.make 1 (char_of_int l)
  else
    let len_len = compute_len 0 l in
    let res = String.make (len_len + 1) (char_of_int len_len) in
    aux res 1 l;
    res

let dump_asn1_object c isC t dump_content v =
  let content_dumped = dump_content v in
  (dump_header c isC t) ^ (dump_length (String.length content_dumped)) ^ content_dumped



let lwt_extract_longtype input =
  let rec aux accu =
    LwtParsingEngine.lwt_parse_uint8 input >>= fun byte ->
    let new_accu = (accu lsl 7) lor (byte land 0x7f) in
    if (byte land 0x80) = 0
    then return new_accu
    else aux new_accu
  in aux 0 >>= fun x -> return (T_Unknown x)

let lwt_extract_header input =
  LwtParsingEngine.lwt_parse_uint8 input >>= fun hdr ->
  let c = extract_class hdr in
  let isC = extract_isConstructed hdr in
  let hdr_t = hdr land 31 in
  if (hdr_t < 0x1f)
  then begin
    if c = C_Universal
    then return (c, isC, asn1_tag_of_int hdr_t)
    else return (c, isC, T_Unknown hdr_t)
  end else begin
    lwt_extract_longtype input >>= fun t ->
    return (c, isC, t)
  end

let lwt_extract_length input =
  LwtParsingEngine.lwt_parse_uint8 input >>= fun first ->
  if first land 0x80 = 0
  then return first
  else begin
    let rec aux accu = function
      | 0 -> return accu
      | i ->
	LwtParsingEngine.lwt_parse_uint8 input >>= fun x ->
	aux ((accu lsl 8) lor x) (i-1)
    in aux 0 (first land 0x7f)
  end

let _lwt_extract_asn1_object name header_constraint parse_content input =
  let offset = input.LwtParsingEngine.lwt_offset in
  lwt_extract_header input >>= fun (c, isC, t) ->
  let fake_input = {
    str = "";
    cur_name = name;
    cur_base = 0;
    cur_offset = offset;
    cur_length = -1;
    history = []
  } in
  check_header header_constraint fake_input c isC t;
  let hlen = input.LwtParsingEngine.lwt_offset - offset in
  lwt_extract_length input >>= fun len ->
  LwtParsingEngine.get_in input name len >>= fun new_input ->
  let asn1_info = {
    a_offset = offset;
    a_hlen = hlen;
    a_length = len;
    a_class = c;
    a_isConstructed = isC;
    a_tag = t;
  }
  and raw_string () = (dump_header c isC t) ^ (dump_length len) ^ new_input.str in
  let res = parse_content new_input in
  LwtParsingEngine.get_out input new_input >>= fun () ->
  return (res, asn1_info, raw_string)

let lwt_extract_asn1_object name header_constraint parse_content input =
  _lwt_extract_asn1_object name header_constraint parse_content input >>= fun (res, _, _) ->
  return res



(* Boolean *)

let parse_der_boolean input =
  let value = parse_rem_list parse_uint8 input in
  match value with
    | [] ->
      emit false BooleanNotInNormalForm input;
      false
    | [0] -> false
    | [255] -> true
    | v::_ ->
      emit false BooleanNotInNormalForm input;
      (v <> 0)

let dump_der_boolean = function
  | true -> String.make 1 '\xff'
  | false -> String.make 1 '\x00'


(* Integer *)

let parse_der_int input =
  let l = parse_rem_string input in
  let two_first_chars =
    let n = String.length l in
    if n = 0 then []
    else if n = 1 then [int_of_char l.[0]]
    else [int_of_char l.[0] ; int_of_char l.[1]]
  in
  begin
    match two_first_chars with
      | [] -> emit false IntegerNotInNormalForm input
      | x::y::_ ->
	if (x = 0xff) || ((x = 0) && (y land 0x80) = 0)
	then emit false IntegerNotInNormalForm input
      | _ -> ()
  end;
  l

let dump_der_int s = s


let parse_der_smallint input =
  let integer_s = parse_der_int input in
  let len = String.length integer_s in
  if (len > 0 && (int_of_char (integer_s.[0]) land 0x80) = 0x80) || (len > 4)
  then raise (Asn1Exception (IntegerOverflow, input))
  else begin
    let rec int_of_binstr accu i =
      if i >= len
      then accu
      else int_of_binstr ((accu lsl 8) + (int_of_char integer_s.[i])) (i+1)
    in int_of_binstr 0 0
  end

let dump_der_smallint i =
  raise (NotImplemented "dump_der_smallint")


(* Null *)

let parse_der_null input =
  if not (eos input)
  then begin
    emit false NullNotInNormalForm input;
    drop_rem_bytes input;
  end

let dump_der_null () = ""


(* OId *)

let parse_subid input : int =
  let rec aux accu =
    let c = parse_uint8 input in
    let new_accu = (accu lsl 7) lor (c land 0x7f) in
    if c land 0x80 != 0
    then aux new_accu
    else new_accu
  in aux 0

let parse_der_oid input =
  let rec aux () =
    if eos input
    then []
    else begin
      try
	let next = parse_subid input in
	next::(aux ())
      with ParsingException (OutOfBounds, i) ->
	emit false OIdNotInNormalForm i;
	[]
    end
  in
  aux ()

(* TODO: dump_der_oid *)

(* let subid_to_charlist id = *)
(*   let rec aux accu x = *)
(*     if x = 0 *)
(*     then accu *)
(*     else aux (((x land 0x7f) lor 0x80)::accu) (x lsr 7) *)
(*   in aux [id land 0x7f] (id lsr 7) *)

(* let oid_to_der idlist = *)
(*   let cll = List.map subid_to_charlist idlist in *)
(*   string_of_int_list (List.flatten cll) *)


(* Bit String *)

let parse_der_bitstring input =
  let nBits =
    if eos input then begin
      emit false (BitStringNotInNormalForm "empty") input;
      0
    end else parse_uint8 input
  in
  let content = parse_rem_string input in
  let len = (String.length content) * 8 - nBits in
  if len < 0
  then emit false (BitStringNotInNormalForm "invalid length") input;
  (* TODO: Check the trailing bits are zeroed. *)
  (nBits, content)

(* TODO: Enumerated Bit Strings *)

(* let apply_desc desc i = *)
(*   if i >= 0 && i < Array.length desc *)
(*   then desc.(i) else raise (OutOfBounds "apply_desc") *)

(* let extract_bit_list s = *)
(*   let n = String.length s in *)
(*   let rec extract_from_byte accu i b = *)
(*     if i = 0 then accu *)
(*     else extract_from_byte (((b land i) <> 0)::accu) (i lsr 1) b *)
(*   in *)
(*   let rec extract_from_str accu offset = *)
(*     if (offset >= n) then List.rev accu *)
(*     else extract_from_str (extract_from_byte accu 0x80 (int_of_char s.[offset])) (offset + 1) *)
(*   in *)
(*   extract_from_str [] 0 *)

(* let name_bits pstate description l = *)
(*   let n = Array.length description in *)
(*   let rec aux i = function *)
(*     | [] -> [] *)
(*     | true::r when i >= n -> *)
(*       asn1_emit NotInNormalForm None (Some "Trailing bits in an enumerated bit string should be null") pstate; *)
(*       [] *)
(*     | true::r -> (i)::(aux (i+1) r) *)
(*     | false::r when i = n -> *)
(*       asn1_emit NotInNormalForm None (Some "Only significant bit should be put inside an enumerated bit string") pstate; *)
(*       aux (i+1) r *)
(*     | false::r -> aux (i+1) r *)
(*   in aux 0 l *)

(* let enumerated_from_raw_bit_string pstate desc nBits content = *)
(*   let len = (String.length content) * 8 - nBits in *)
(*   if len > Array.length desc *)
(*   then asn1_emit NotInNormalForm None (Some "Bit string is too long") pstate; *)
(*   let bits = extract_bit_list content in *)
(*   name_bits pstate desc bits *)

(* TODO: dump_der_bitstring *)

(* let der_to_bitstring description pstate = *)
(*   let nBits, content = raw_der_to_bitstring pstate in *)
(*   match description with *)
(*     | None -> BitString (nBits, content) *)
(*     | Some desc -> *)
(*       if !parse_enumerated *)
(*       then EnumeratedBitString (enumerated_from_raw_bit_string pstate desc nBits content, desc) *)
(*       else BitString (nBits, content) *)


(* Octet String *)

let no_constraint s _ = s

let utc_time_re =
  Str.regexp "^\\([0-9][0-9]\\)\\([0-9][0-9]\\)\\([0-9][0-9]\\)\\([0-9][0-9]\\)\\([0-9][0-9]\\)\\([0-9][0-9]\\)Z$"
let generalized_time_re =
  Str.regexp "^\\([0-9][0-9][0-9][0-9]\\)\\([0-9][0-9]\\)\\([0-9][0-9]\\)\\([0-9][0-9]\\)\\([0-9][0-9]\\)\\([0-9][0-9]\\)Z$"

let time_constraint re s input =
  try
    if Str.string_match re s 0 then begin
      let y = int_of_string (Str.matched_group 1 s)
      and m = int_of_string (Str.matched_group 2 s)
      and d = int_of_string (Str.matched_group 3 s)
      and hh = int_of_string (Str.matched_group 4 s)
      and mm = int_of_string (Str.matched_group 5 s)
      and ss = int_of_string (Str.matched_group 6 s) in
      if m = 0 || m > 12 || d = 0 || d > 31 || hh >= 24 || mm > 59 || ss > 59
      then emit false InvalidUTCTime input;
      (y, m, d, hh, mm, ss)
    end else raise (Asn1Exception (InvalidUTCTime, input))
  with _ -> raise (Asn1Exception (InvalidUTCTime, input))

let utc_time_constraint = time_constraint utc_time_re
let generalized_time_constraint = time_constraint generalized_time_re

let parse_der_octetstring apply_constraints input =
  let res = parse_rem_string input in
  apply_constraints res input

let parse_der_octetstring_s apply_constraints input =
  let res = parse_rem_string input in
  ignore (apply_constraints res input);
  res

let dump_der_octetstring s = s



(* Sequence/Set of *)

let parse_der_list name header_constraint min max parse_content input =
  let rec parse_aux accu =
    if eos input
    then List.rev accu
    else
      let next = extract_asn1_object name header_constraint parse_content input in
      parse_aux (next::accu)
  in
  let res = parse_aux [] in
  let len = List.length res in
  let real_min = pop_opt len min
  and real_max = pop_opt len max in
  if len < real_min then emit false (TooFewObjects (len, real_min)) input;
  if len > real_max then emit false (TooManyObjects (len, real_max)) input;
  res

(* TODO: dump_der_list *)



(* Generic ASN.1 Object *)

type asn1_object = {
  a_class : asn1_class;
  a_tag : asn1_tag;
  a_content : asn1_content;
}

and asn1_content =
  | Boolean of bool
  | Integer of string
  | BitString of int * string
(*  | EnumeratedBitString of (int list) * bitstring_description *)
  | Null
  | OId of int list
  | String of (string * bool)       (* bool : isBinary *)
  | Constructed of asn1_object list


let rec parse_asn1_object input =
  let _offset = input.cur_base + input.cur_offset in
  let old_cur_offset = input.cur_offset in
  let c, isC, t = extract_header input in
  let len = extract_length input in
  let _hlen = input.cur_offset - old_cur_offset in
  let new_input = get_in input (print_header (c, isC, t)) len in
  let content = match c, isC, t with
    | (C_Universal, false, T_Boolean) -> Boolean (parse_der_boolean new_input)
    | (C_Universal, false, T_Integer) -> Integer (parse_der_int new_input)
    | (C_Universal, false, T_Null) -> parse_der_null new_input; Null
    | (C_Universal, false, T_OId) -> OId (parse_der_oid new_input)
    | (C_Universal, false, T_BitString) -> let nBits, s = parse_der_bitstring input in BitString (nBits, s)
    | (C_Universal, false, T_OctetString) -> String (parse_der_octetstring no_constraint new_input, true)

    | (C_Universal, false, T_UTF8String)
    | (C_Universal, false, T_NumericString)
    | (C_Universal, false, T_PrintableString)
    | (C_Universal, false, T_T61String)
    | (C_Universal, false, T_VideoString)
    | (C_Universal, false, T_IA5String) -> String (parse_der_octetstring no_constraint new_input, false) (* TODO *)
    | (C_Universal, false, T_UTCTime) -> String (parse_der_octetstring_s utc_time_constraint new_input, false)
    | (C_Universal, false, T_GeneralizedTime) -> String (parse_der_octetstring_s generalized_time_constraint new_input, false)
    | (C_Universal, false, T_GraphicString)
    | (C_Universal, false, T_VisibleString)
    | (C_Universal, false, T_GeneralString)
    | (C_Universal, false, T_UniversalString)
    | (C_Universal, false, T_UnspecifiedCharacterString)
    | (C_Universal, false, T_BMPString) -> String (parse_der_octetstring no_constraint input, false) (* TODO *)

    | (C_Universal, true, T_Sequence)
    | (C_Universal, true, T_Set) -> Constructed (parse_der_constructed new_input)

    | (C_Universal, false, t) ->
      emit false (UnknownUniversalObject (false, t)) new_input;
      String (parse_der_octetstring no_constraint new_input, true)

    | (C_Universal, true, t) ->
      emit false (UnknownUniversalObject (true, t)) new_input;
      Constructed (parse_der_constructed new_input)

    | (_, false, _) -> String (parse_der_octetstring no_constraint new_input, true)
    | (_, true, _)  -> Constructed (parse_der_constructed new_input)
  in
  get_out input new_input;
 {
    a_class = c;
    a_tag = t;
    a_content = content;
  }

and parse_der_constructed input =
  let rec parse_aux accu =
    if eos input
    then List.rev accu
    else
      let next = parse_asn1_object input in
      parse_aux (next::accu)
  in parse_aux []

(* TODO: dump_asn1_object *)





(* (\**************************\) *)
(* (\* Content pretty printer *\) *)
(* (\**************************\) *)

(* (\* Useful func *\) *)

(* let isConstructed o = match o.a_content with *)
(*   | Constructed _ -> true *)
(*   | _ -> false *)


(* let string_of_bitstring raw nBits s = *)
(*   if raw || nBits <> 0 *)
(*   then "[" ^ (string_of_int nBits) ^ "]:" ^ (hexdump s) *)
(*   else hexdump s *)

(* let oid_expand = function *)
(*   | [] -> [] *)
(*   | x::r -> *)
(*     let a, b = if x >= 80 *)
(*       then 2, (x - 80) *)
(*       else (x / 40), (x mod 40) *)
(*     in a::b::r *)

(* let oid_squash = function *)
(*   | a::b::r -> *)
(*     if ((a = 0 || a = 1) && (b < 40)) || (a = 2) *)
(*     then (a * 40 + b)::r *)
(*     else raise (ContentError ("Invalid OId")) *)
(*   | _ -> raise (ContentError ("Invalid OId")) *)


(* let (name_directory : (int list, string) Hashtbl.t) = Hashtbl.create 100 *)
(* let (rev_name_directory : (string, int list) Hashtbl.t) = Hashtbl.create 200 *)

(* let raw_string_of_oid oid = *)
(*   String.concat "." (List.map string_of_int (oid_expand oid)) *)

(* let register_oid oid s = *)
(*   Hashtbl.add name_directory oid s; *)
(*   Hashtbl.add rev_name_directory s oid; *)
(*   Hashtbl.add rev_name_directory (raw_string_of_oid oid) oid *)

(* let string_of_oid oid = *)
(*   if !PrinterLib.resolve_names then *)
(*     try Hashtbl.find name_directory oid *)
(*     with Not_found -> raw_string_of_oid oid *)
(*   else raw_string_of_oid oid *)


(* let rec string_of_content = function *)
(*   | Constructed l -> *)
(*     let objects = List.map string_of_object l in *)
(*     PrinterLib._flatten_strlist [] true objects *)
(*   | Null -> [], false *)
(*   | Boolean true -> ["true"], false *)
(*   | Boolean false -> ["false"], false *)
(*   | Integer i -> ["0x" ^ (hexdump i)], false *)
(*   | BitString (nBits, s) -> [string_of_bitstring !PrinterLib.raw_display nBits s], false *)
(*   | EnumeratedBitString (l, desc) -> ["[" ^ (String.concat ", " (List.map (apply_desc desc) l)) ^ "]"], false *)
(*   | OId oid -> [string_of_oid oid], false *)
(*   | String (s, true) -> ["[HEX:]" ^ (hexdump s)], false *)
(*   | String (s, false) -> [if !PrinterLib.raw_display then hexdump s else s], false *)

(* and string_of_object o = *)
(*   let type_string = *)
(*     if !PrinterLib.raw_display *)
(*     then string_of_header_raw o.a_class (isConstructed o) o.a_tag *)
(*     else begin *)
(*       if !PrinterLib.resolve_names *)
(*       then o.a_name *)
(*       else string_of_header_pretty o.a_class (isConstructed o) o.a_tag *)
(*     end *)
(*   in *)
(*   let content_string, multiline = string_of_content o.a_content in *)
(*   if multiline *)
(*   then PrinterLib._string_of_strlist (Some type_string) (hash_options "" true) content_string *)
(*   else PrinterLib._string_of_strlist (Some type_string) (only_ml false) content_string *)







(* let bitstring_to_der nBits s = *)
(*   let prefix = String.make 1 (char_of_int nBits) in *)
(*   prefix ^ s *)



(* let rec dump o = *)
(*   let isC, contents = match o.a_content with *)
(*     | Null -> false, "" *)
(*     | Boolean b -> false, boolean_to_der b *)
(*     | Integer i -> false, i *)
(*     | BitString (nb, s) -> false, bitstring_to_der nb s *)
(*     | EnumeratedBitString (l, _) -> raise (NotImplemented "asn1.dump (EnumeratedBitString)") (\* TODO *\) *)
(*     | OId id -> false, oid_to_der id *)
(*     | String (s, _) -> false, s *)
(*     | Constructed objects -> true, constructed_to_der objects *)
(*   in *)
(*   let hdr = dump_header o.a_class isC o.a_tag in *)
(*   let lg = dump_length (String.length contents) in *)
(*   hdr ^ lg ^ contents *)

(* and constructed_to_der objlist = *)
(*   let subdumps = List.map dump objlist in *)
(*   String.concat "" subdumps *)




(* module Asn1Parser = struct *)
(*   type t = asn1_object *)
(*   let name = "asn1" *)
(*   let params = [param_from_bool_ref "parse_enumerated" parse_enumerated] *)

(*   let parse = parse *)
(*   let dump = dump *)

(*   let class_of_string = function *)
(*     | "Universal" -> C_Universal *)
(*     | "Application" -> C_Application *)
(*     | "Context Specific" -> C_ContextSpecific *)
(*     | "Private" -> C_Private *)
(*     | _ -> raise (ContentError ("Invalid ASN.1 class")) *)

(*   let value_of_oid oid = *)
(*     V_List (List.map (fun x -> V_Int x) (oid_expand oid)) *)

(*   let rec value_of_asn1_content = function *)
(*     | Null -> V_Unit *)
(*     | Boolean b -> V_Bool b *)
(*     | Integer i -> V_Bigint i *)
(*     | BitString (n, s) -> V_BitString (n, s) *)
(*     | EnumeratedBitString (l, desc) -> *)
(*       let f = apply_desc desc in *)
(*       V_List (List.map (fun x -> V_Enumerated (x, f)) l) *)
(*     | OId oid -> value_of_oid oid *)
(*     | String (s, true) -> V_BinaryString s *)
(*     | String (s, false) -> V_String s *)
(*     | Constructed objs -> *)
(*       let value_of_constructed sub_obj = *)
(* 	let d = Hashtbl.create 10 in *)
(* 	enrich sub_obj d; *)
(* 	V_Dict d *)
(*       in *)
(*       V_List (List.map value_of_constructed objs) *)

(*   and enrich o dict = *)
(*     Hashtbl.replace dict "name" (V_String o.a_name); *)
(*     Hashtbl.replace dict "class" (V_String (string_of_class o.a_class)); *)
(*     Hashtbl.replace dict "tag" (V_Int (o.a_tag)); *)
(*     Hashtbl.replace dict "tag_str" (V_String (string_of_tag o.a_class o.a_tag)); *)
(*     Hashtbl.replace dict "is_constructed" (V_Bool (isConstructed o)); *)
(*     begin *)
(*       match o.a_ohl with *)
(* 	| None -> () *)
(* 	| Some (off, hlen, len) -> *)
(* 	  Hashtbl.replace dict "offset" (V_Int off); *)
(* 	  Hashtbl.replace dict "hlen" (V_Int hlen); *)
(* 	  Hashtbl.replace dict "len" (V_Int len); *)
(*     end; *)
(*     Hashtbl.replace dict "content" (value_of_asn1_content o.a_content) *)

(*   let oid_of_list v = oid_squash (List.map eval_as_int v) *)

(*   let rec asn1_content_of_value = function *)
(*     | false, V_Unit -> Null *)
(*     | false, V_Bool b -> Boolean b *)
(*     | false, V_Bigint i -> Integer i *)
(*     | false, V_BitString (n, s) -> BitString (n, s) *)
(*     | false, V_BinaryString s -> String (s, true) *)
(*     | false, V_String s -> String (s, false) *)
(*     | false, V_List ((V_Int _::r) as l) -> OId (oid_of_list l) *)
(*     | false, V_List l -> raise (NotImplemented "asn1_content_of_value (V_List [EnumeratedBitString])") (\* TODO *\) *)
(*     | true, V_List l -> *)
(*       Constructed (List.map (fun x -> update (eval_as_dict x)) l) *)
(*     | _ -> raise (ContentError ("Invalid value for an asn1 content")) *)

(*   and update dict = *)
(*     let name = eval_as_string (hash_find dict "name") in *)
(*     let c = class_of_string (eval_as_string (hash_find dict "class")) in *)
(*     let t = eval_as_int (hash_find dict "tag") in *)
(*     let isC = eval_as_bool (hash_find dict "is_constructed") in *)
(*     let content = asn1_content_of_value (isC, hash_find dict "content") in *)
(*     mk_object' name c t content *)


(*   let to_string = string_of_object *)

(*   let functions = [] *)
(* end *)

(* module Asn1Module = MakeParserModule (Asn1Parser) *)
(* let _ = add_object_module ((module Asn1Module : ObjectModule)) *)
