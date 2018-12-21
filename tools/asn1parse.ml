open Parsifal
open Asn1Engine
open Asn1PTypes
open Getopt
open PTypes
open Base64

let indent = ref false
let keep_going = ref false
let openssl_mode = ref false

type input_style = Hex | PEM | Raw
let input_style = ref PEM
let set_input_style v () = input_style := v

let base64_header = ref (AnyHeader)
let set_b64_header s =
  base64_header := HeaderInList [s];
  ActionDone


let options = [
  mkopt (Some 'h') "help" Usage "show this help";
  mkopt (Some 'i') "indent" (Set indent) "indent the elements";
  mkopt (Some 'k') "keep-going" (Set keep_going) "keep working even when errors arise";
  mkopt (Some 'o') "openssl-mode" (Set openssl_mode) "mimic the output of openssl asn1parse";
  mkopt None "pem" (TrivialFun (set_input_style PEM)) "use PEM format (default)";
  mkopt None "der" (TrivialFun (set_input_style Raw)) "use DER (raw, binary) format";
  mkopt None "hex" (TrivialFun (set_input_style Hex)) "use hex format";
  mkopt None "pem-header" (StringFun (set_b64_header)) "specify the header/trailer expected for PEM format";
  mkopt None "no-pem-header" (TrivialFun (fun () -> base64_header := NoHeader)) "do not expect header/trailer for PEM format";

  mkopt (Some 'n') "numeric" (Clear resolve_oids) "show numerical fields (do not resolve OIds)";
  mkopt None "resolve-oids" (Set resolve_oids) "show OID names";
]

 
(* TODO: Should some of this code be factored in asn1Engine? *)

let name_of_ct = function
  | (C_Universal, false, T_Boolean) -> "BOOLEAN"
  | (C_Universal, false, T_Integer) -> "INTEGER"
  | (C_Universal, false, T_Null) -> "NULL"
  | (C_Universal, false, T_OId) -> "OBJECT"
  | (C_Universal, false, T_BitString) -> "BIT STRING"
  | (C_Universal, false, T_OctetString) -> "OCTET STRING"
  | (C_Universal, false, T_UTF8String) -> "UTF8STRING"
  | (C_Universal, false, T_NumericString) -> "NUMERICSTRING"
  | (C_Universal, false, T_PrintableString) -> "PRINTABLESTRING"
  | (C_Universal, false, T_T61String) -> "T61STRING"
  | (C_Universal, false, T_VideoString) -> "VIDEOSTRING"
  | (C_Universal, false, T_IA5String) -> "IA5STRING"
  | (C_Universal, false, T_UTCTime) -> "UTCTIME"
  | (C_Universal, false, T_GeneralizedTime) -> "GENERALIZEDTIME"
  | (C_Universal, false, T_GraphicString) -> "GRAPHICSTRING"
  | (C_Universal, false, T_VisibleString) -> "VISIBLESTRING"
  | (C_Universal, false, T_GeneralString) -> "GENERALSTRING"
  | (C_Universal, false, T_UniversalString) -> "UNIVERSALSTRING"
  | (C_Universal, false, T_UnspecifiedCharacterString) -> "UNSPECIFIEDSTRING"
  | (C_Universal, false, T_BMPString) -> "BMPSTRING"
  | (C_Universal, true, T_Sequence) -> "SEQUENCE"
  | (C_Universal, true, T_Set) -> "SET"
  | (C_Universal, _, t) when !openssl_mode -> Printf.sprintf "prim [ %d ]" (int_of_asn1_tag t)
  | (C_ContextSpecific, _, t) when !openssl_mode -> Printf.sprintf "cont [ %d ]" (int_of_asn1_tag t)
  | (C_Private, _, t) when !openssl_mode -> Printf.sprintf "priv [ %d ]" (int_of_asn1_tag t)
  | (C_Application, _, t) when !openssl_mode -> Printf.sprintf "appl [ %d ]" (int_of_asn1_tag t)
  | (C_Universal, _, t) -> Printf.sprintf "prim [%d]" (int_of_asn1_tag t)
  | (C_ContextSpecific, _, t) -> Printf.sprintf "cont [%d]" (int_of_asn1_tag t)
  | (C_Private, _, t) -> Printf.sprintf "priv [%d]" (int_of_asn1_tag t)
  | (C_Application, _, t) -> Printf.sprintf "appl [%d]" (int_of_asn1_tag t)

let print_line offset depth hlen len isC c t =
  Printf.printf "%5d:d=%d  hl=%d l=%4d %s: %s%-18s"
    offset depth hlen len (if isC then "cons" else "prim")
    (if !indent then String.make depth ' ' else "")
    (name_of_ct (c, isC, t))


(* TODO: Rethink the lwt flavour? *)
let rec parse lwt_base depth input =
  if not (eos input) then begin
    let offset = lwt_base + input.cur_base + input.cur_offset
    and saved_offset = input.cur_offset in
    let (c, isC, t) = extract_der_header input in
    let len = extract_der_length input in
    let hlen = input.cur_offset - saved_offset in
    print_line offset depth hlen len isC c t;
    let new_input = get_in input (print_header (c, isC, t)) len in 
    parse_content lwt_base depth (c, isC, t) new_input;
    get_out input new_input;
    parse lwt_base depth input
  end

and parse_content lwt_base depth (c, isC, t) input =
  if not isC then begin
    let res = match (c, t) with
    | (C_Universal, T_Boolean) -> string_of_bool (parse_der_boolean_content input)
    | (C_Universal, T_Integer) -> hexdump (parse_der_integer_content input)
    | (C_Universal, T_Null) -> parse_der_null_content input; ""
    | (C_Universal, T_OId) -> string_of_oid (parse_der_oid_content input)
    | (C_Universal, T_BitString) ->
      let _nBits, s = parse_der_bitstring_content input in
      if !openssl_mode then "" else hexdump s
    | (C_Universal, T_UTF8String)
    | (C_Universal, T_NumericString)
    | (C_Universal, T_PrintableString)
    | (C_Universal, T_T61String)
    | (C_Universal, T_VideoString)
    | (C_Universal, T_IA5String) -> parse_der_octetstring_content no_constraint input
    | (C_Universal, T_UTCTime) -> parse_der_octetstring_content utc_time_constraint input
    | (C_Universal, T_GeneralizedTime) -> parse_der_octetstring_content generalized_time_constraint input
    | (C_Universal, T_GraphicString)
    | (C_Universal, T_VisibleString)
    | (C_Universal, T_GeneralString)
    | (C_Universal, T_UniversalString)
    | (C_Universal, T_UnspecifiedCharacterString)
    | (C_Universal, T_BMPString) -> parse_der_octetstring_content no_constraint input

    | (C_Universal, T_OctetString)
    | _ -> hexdump (parse_der_octetstring_content no_constraint input)
    in
    if res = ""
    then print_newline ()
    else Printf.printf ":%s%s\n"
      (if !openssl_mode then "" else " ") res
  end else begin
    print_newline ();
    parse lwt_base (depth+1) input
  end


let _ =
  let args = parse_args ~progname:"asn1parse" options Sys.argv in
  let parse_fun =
    match !input_style with
    | Hex -> parse_hex_container "hex_container" (parse 0 0)
    | PEM -> parse_base64_container !base64_header "base64_container" (parse 0 0)
    | Raw -> parse 0 0
  in
  try
    match args with
    | [] -> parse_fun (string_input_of_stdin ())
    | _  ->
      let aux fn =
	try parse_fun (string_input_of_filename fn)
	with e ->
	  if !keep_going
	  then prerr_endline (Printexc.to_string e)
	  else raise e
      in
      List.iter aux args
  with
    | End_of_file -> ()
    | ParsingException (e, h) ->
      flush stdout; prerr_endline (string_of_exception e h); exit 1
    | e ->
      flush stdout; prerr_endline (Printexc.to_string e); exit 1
