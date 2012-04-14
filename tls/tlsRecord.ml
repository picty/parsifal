open Common
open Types
open Modules
open Printer
open ParsingEngine
open TlsCommon
open TlsChangeCipherSpec
open TlsAlert
open TlsHandshake


type tls_record_errors =
  | UnexpectedContentType

let tls_record_errors_strings =
  [| (UnexpectedContentType, s_benign, "Unexpected content type") |]

let tls_record_emit = register_module_errors_and_make_emit_function "tlsRecord" tls_record_errors_strings



(* Content type *)

type content_type = int

let content_type_string_of_int = function
  | 20 -> "ChangeCipherSpec"
  | 21 -> "Alert"
  | 22 -> "Handshake"
  | 23 -> "ApplicationData"
  | x -> "Unknown content type " ^ (string_of_int x)

let content_type_int_of_string = function
  | "ChangeCipherSpec" -> 20
  | "Alert" -> 21
  | "Handshake" -> 22
  | "ApplicationData" -> 23
  | s -> int_of_string s

let check_content_type pstate = function
  | 20 | 21 | 22 | 23 -> ()
  | x -> tls_record_emit UnexpectedContentType None (Some (string_of_int x)) pstate

let pop_content_type pstate =
  let ct = pop_byte pstate in
  check_content_type pstate ct;
  ct

let _make_content_type = function
  | V_Int i
  | V_Enumerated (i, _) -> i
  | V_String s -> content_type_int_of_string s
  | _ -> raise (ContentError "Invalid content type value")

let make_content_type v = V_Enumerated (_make_content_type v, content_type_string_of_int)



(* Record type *)

type record_type = {
  version : protocol_version;
  content_type : content_type;
  content : value
}



module RecordParser = struct
  let name = "record"
  type t = record_type

  let parse pstate =
    let ctype = pop_content_type pstate in
    let version = pop_uint16 pstate in
    let len = pop_uint16 pstate in
    let content = pop_fixedlen_string len pstate in
    { version = version;
      content_type = ctype;
      content = V_BinaryString content }

  let dump record =
    let content_dump = match record.content_type, record.content with
      | _, V_BinaryString s -> s
      | 0x14, (V_Object ("change_cipher_spec", _, _) as o) -> ChangeCipherSpecParser.dump (ChangeCipherSpecModule.pop_object o)
      | 0x15, (V_Object ("alert", _, _) as o) -> AlertParser.dump (AlertModule.pop_object o)
      | 0x16, (V_Object ("handshake", _, _) as o) -> HandshakeParser.dump (HandshakeModule.pop_object o)
      | _ -> raise (NotImplemented "record.dump")
    in
    (dump_uint8 record.content_type) ^ (dump_uint16 record.version) ^ (dump_uint16 (String.length content_dump)) ^ content_dump
    

  let enrich record dict =
    Hashtbl.replace dict "content_type" (V_Enumerated (record.content_type, content_type_string_of_int));
    Hashtbl.replace dict "version" (V_String (protocol_version_string_of_int record.version));
    Hashtbl.replace dict "content" record.content;
    ()

  let update dict =
    { version = _make_protocol_version (hash_find dict "version");
      content_type = _make_content_type (hash_find dict "content_type");
      content = hash_find dict "content" }

  let to_string r =
    let hdr = "TLS Record (" ^ (protocol_version_string_of_int r.version) ^ ", " ^
      (content_type_string_of_int r.content_type) ^ ")" in
    match r.content with
      | (V_BinaryString s | V_String s) as str ->
	let strs = (PrinterLib._single_line (Some "Length") (string_of_int (String.length s)))::
	  (PrinterLib._string_of_value (Some "Content") true str) in
	PrinterLib._string_of_strlist (Some hdr) indent_only strs
      | c -> PrinterLib._string_of_value (Some hdr) true c


  let merge records =
    let rec merge_aux current accu records = match current, records with
      | None, [] -> List.rev accu
      | Some r, [] -> List.rev (r::accu)
      | None, r::rem ->
	if r.content_type = 0x16
	then merge_aux (Some r) accu rem
	else merge_aux None (r::accu) rem
      | Some r1, r2::rem ->
	if (r1.version = r2.version && r1.content_type = r2.content_type)
	(* TODO: Here we might lose some info about the exact history... *)
	then begin
	  let new_content = V_BinaryString ((eval_as_string r1.content) ^ (eval_as_string r2.content)) in
	  merge_aux (Some {r1 with content = new_content}) accu rem
	end else merge_aux None (r1::accu) records
    in merge_aux None [] records

  let wrapped_merge (pop_object, register) = function
    | [V_List records] ->
      let raw_records = List.map pop_object records in
      let merged_records = merge raw_records in
      let result = List.map register merged_records in
      V_List (result)
    | [_] -> raise (ContentError ("List of Tls Records expected."))
    | _ -> raise WrongNumberOfArguments

  let params = []
  let functions = ["merge", wrapped_merge, Some 1]
end

module RecordModule = MakeParserModule (RecordParser)


let _ = add_object_module ((module RecordModule : ObjectModule))
