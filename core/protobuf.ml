open Lwt
open Parsifal
open BasePTypes

(* Varint *)

type varint = int

(* let varint_of_bytelist bytes h = *)
(*   let rec add_bytes accu = function *)
(*     | [] -> accu *)
(*     | x::r -> add_bytes ((accu lsl 7) lor x) r *)
(*   in *)
(*   if (List.length bytes) > 4 *)
(*   then raise (ParsingException (NotImplemented "parse_varint on more than 4 bytes", h)); *)
(*   let base = match bytes with *)
(*     | [] -> 0 *)
(*     | x::_ -> *)
(*       if (x land 0x40) == 0 then 0 else -1 *)
(*   in add_bytes base bytes *)

let varint_of_bytelist bytes h =
  let rec add_bytes accu = function
    | [] -> accu
    | x::r -> add_bytes ((accu lsl 7) lor x) r
  in
  if (List.length bytes) > 4
  then raise (ParsingException (NotImplemented "parse_varint on more than 4 bytes", h));
  add_bytes 0 bytes

let parse_varint input =
  let rec parse_bytelist accu input =
    let b = parse_byte input in
    if (b land 0x80) == 0
    then b::accu
    else parse_bytelist ((b land 0x7f)::accu) input
  in
  let bytes = parse_bytelist [] input in
  varint_of_bytelist bytes (_h_of_si input)

let lwt_parse_varint lwt_input =
  let rec lwt_parse_bytelist accu lwt_input =
    lwt_parse_byte lwt_input >>= fun b ->
    if (b land 0x80) == 0
    then return (b::accu)
    else lwt_parse_bytelist ((b land 0x7f)::accu) lwt_input
  in
  lwt_parse_bytelist [] lwt_input >>= fun bytes ->
  return (varint_of_bytelist bytes (_h_of_li lwt_input))

let dump_varint _ = not_implemented "dump_varint"

let string_of_varint i = Printf.sprintf "%d (%x)" i i
let print_varint ?indent:(indent="") ?name:(name="char") i =
  Printf.sprintf "%s%s: %d (%x)\n" indent name i i

let get_varint = trivial_get dump_varint string_of_varint

let value_of_varint i = VSimpleInt i


(* Protobuf key *)

enum wire_type (3, Exception UnknownWireType) =
  | 0 -> WT_Varint, "Varint"
  | 1 -> WT_Fixed64bit, "Fixed64bit"
  | 2 -> WT_LengthDelimited, "LengthDelimited"
  | 3 -> WT_StartGroup, "StartGroup"
  | 4 -> WT_EndGroup, "EndGroup"
  | 5 -> WT_Fixed32bit, "Fixed32bit"

type protobuf_key = wire_type * int

let parse_protobuf_key input =
  let x = parse_varint input in
  (wire_type_of_int (x land 7), x lsr 3)

let lwt_parse_protobuf_key lwt_input =
  lwt_parse_varint lwt_input >>= fun x ->
  return (wire_type_of_int (x land 7), x lsr 3)

let dump_protobuf_key (wt, fn) =
  dump_varint ((fn lsl 3) lor (int_of_wire_type wt))

let string_of_protobuf_key (wt, fn) =
  Printf.sprintf "(%s, %d)" (string_of_wire_type wt) fn

let print_protobuf_key ?indent:(indent="") ?name:(name="protobuf_key") (wt, fn) =
  Printf.sprintf "%s%s: (%s, %d)\n" indent name (string_of_wire_type wt) fn

let get_protobuf_key = trivial_get dump_protobuf_key string_of_protobuf_key

let value_of_protobuf_key (wt, fn) =
  VRecord ["wire_type", value_of_wire_type wt;
	   "field_number", VSimpleInt fn]


(* Length defined stuff *)

let parse_length_delimited_container parse_fun input =
  let len = parse_varint input in
  parse_container "length_delimited_container" len parse_fun input

let lwt_parse_length_delimited_container parse_fun lwt_input =
  lwt_parse_varint lwt_input >>= fun len ->
  lwt_parse_container "length_delimited_container" len parse_fun lwt_input

let dump_length_delimited_container dump_fun v =
  dump_container dump_varint dump_fun v



(* Protobuf value *)

alias bothstring = binstring
let string_of_bothstring s =
  Printf.sprintf "%s (%s)" (hexdump s) (quote_string s)
let print_bothstring ?indent:(indent="") ?name:(name="both_string") s =
  Printf.sprintf "%s%s: %s (%s)\n" indent name (hexdump s) (quote_string s)

union protobuf_value [enrich; exhaustive; with_lwt] (Unparsed_Protobuf) =
  | WT_Varint, _ -> Varint of varint
  | WT_Fixed64bit, _ -> Fixed64bit of binstring(8)
  | WT_LengthDelimited, _ -> LengthDelimited of (length_delimited_container of bothstring)
  | WT_StartGroup, _ -> StartGroup
  | WT_EndGroup, _ -> EndGroup
  | WT_Fixed32bit, _ -> Fixed32bit of uint32




(* Simple Protobuf key/value *)

struct protobuf [top] = {
  key : protobuf_key;
  value : protobuf_value (key)
}



(* Recursive parsing *)

type rec_protobuf_value =
  | R_Varint of varint
  | R_Fixed64bit of string
  | R_String of string
  | R_List of rec_protobuf list
  | R_StartGroup
  | R_EndGroup
  | R_Fixed32bit of int

and rec_protobuf = int * rec_protobuf_value

let rec parse_rec_protobuf input =
  let protobuf = parse_protobuf input in
  let v = match protobuf.value with
    | Varint i -> R_Varint i
    | Fixed64bit s -> R_Fixed64bit s
    | LengthDelimited s -> begin
      let new_input = input_of_string ("Field number " ^ (string_of_int (snd protobuf.key))) s in
      try R_List (parse_rem_list parse_rec_protobuf new_input)
      with _ -> R_String s
    end
    | StartGroup -> R_StartGroup
    | EndGroup -> R_EndGroup
    | Fixed32bit i -> R_Fixed32bit i
    | Unparsed_Protobuf _ ->
      raise (ParsingException (CustomException "parse_rec_protobuf on Unparsed_Protobuf", _h_of_si input))
  in (snd protobuf.key, v)

let lwt_parse_rec_protobuf lwt_input =
  lwt_parse_protobuf lwt_input >>= fun protobuf ->
  try
    let v = match protobuf.value with
      | Varint i -> R_Varint i
      | Fixed64bit s -> R_Fixed64bit s
      | LengthDelimited s -> begin
        let new_input = input_of_string ("Field number " ^ (string_of_int (snd protobuf.key))) s in
        try R_List (parse_rem_list parse_rec_protobuf new_input)
        with _ -> R_String s
      end
      | StartGroup -> R_StartGroup
      | EndGroup -> R_EndGroup
      | Fixed32bit i -> R_Fixed32bit i
      | Unparsed_Protobuf _ ->
        raise (ParsingException (CustomException "lwt_parse_rec_protobuf on Unparsed_Protobuf", _h_of_li lwt_input))
    in return (snd protobuf.key, v)
  with e -> fail e


let rec print_rec_protobuf ?indent:(indent="") ?name:(name="rec_protobuf") (num, value) =
  let default_fun t v =
    Printf.sprintf "%s%s_%s: %s\n" indent t (string_of_int num) (string_of_protobuf_value v)
  in
  match value with
  | R_Varint i -> default_fun "Varint" (Varint i)
  | R_Fixed64bit s -> default_fun "Fixed64bit" (Fixed64bit s)
  | R_String s -> default_fun "String" (LengthDelimited s)
  | R_List l -> print_list ~indent:indent ~name:("Seq_" ^ (string_of_int num)) print_rec_protobuf l
  | R_StartGroup -> default_fun "StartGroup" StartGroup
  | R_EndGroup -> default_fun "StartGroup" EndGroup
  | R_Fixed32bit i -> default_fun "Fixed32bit" (Fixed32bit i)
