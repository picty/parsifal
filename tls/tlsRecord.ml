open Types
open Modules
open NewParsingEngine


(* Protocol version *)

type protocol_version = { major : int; minor : int }

let string_of_protocol_version v = match (v.major, v.minor) with
  | 2, 0 -> "SSLv2"
  | 3, 0 -> "SSLv3"
  | 3, 1 -> "TLSv1.0"
  | 3, 2 -> "TLSv1.1"
  | 3, 3 -> "TLSv1.2"
  | maj, min -> "version" ^ (string_of_int maj) ^ "." ^ (string_of_int min)



(* Content type *)

type content_type =
  | CT_ChangeCipherSpec
  | CT_Alert
  | CT_Handshake
  | CT_ApplicationData
  | CT_Unknown of int

let string_of_content_type = function
  | CT_ChangeCipherSpec -> "ChangeCipherSpec"
  | CT_Alert -> "Alert"
  | CT_Handshake -> "Handshake"
  | CT_ApplicationData -> "ApplicationData"
  | CT_Unknown x -> "Unknown content type " ^ (string_of_int x)

let content_type_of_int pstate = function
  | 20 -> CT_ChangeCipherSpec
  | 21 -> CT_Alert
  | 22 -> CT_Handshake
  | 23 -> CT_ApplicationData
  | x ->
    emit (* (UnexpectedContentType x) TODO *) (123, None) s_benign pstate;
    CT_Unknown x


(* Record type *)

type record_type = {
  version : protocol_version;
  content_type : content_type;
  content : string
}



module RecordParser = struct
  let name = "record"
  type t = record_type

  let mk_ehf () = default_error_handling_function None 0 0

  (* TODO: Should disappear soon... *)
  type pstate = NewParsingEngine.parsing_state
  let pstate_of_string = NewParsingEngine.pstate_of_string (mk_ehf ())
  let pstate_of_stream = NewParsingEngine.pstate_of_stream (mk_ehf ())
  (* TODO: End of blob *)

  let parse pstate =
    let ctype = content_type_of_int pstate (pop_byte pstate) in
    let maj = pop_byte pstate in
    let min = pop_byte pstate in
    let len = extract_uint16 pstate in
    let content = extract_string (string_of_content_type ctype) len pstate in
    Some { version = {major = maj; minor = min};
	   content_type = ctype;
	   content = content }

  let dump record = raise NotImplemented

  let enrich record dict =
    Hashtbl.replace dict "content_type" (V_String (string_of_content_type (record.content_type)));
    Hashtbl.replace dict "version" (V_String (string_of_protocol_version record.version));
    Hashtbl.replace dict "content" (V_BinaryString record.content);
    ()

  let update dict = raise NotImplemented

  let to_string r =
    "TLS Record (" ^ (string_of_protocol_version r.version) ^
      "): " ^ (string_of_content_type r.content_type) ^
      "\n    Length:  " ^ (string_of_int (String.length r.content)) ^
      "\n    Content: " ^ (Common.hexdump r.content) ^ "\n"


  let merge records =
    let rec merge_aux current accu records = match current, records with
      | None, [] -> []
      | Some r, [] -> List.rev (r::accu)
      | None, r::rem -> merge_aux (Some r) accu rem
      | Some r1, r2::rem ->
	if (r1.version = r2.version && r1.content_type == r2.content_type)
	(* TODO: Here we might lose some info about the exact history... *)
	then merge_aux (Some {r1 with content = r1.content ^ r2.content}) accu rem
	else merge_aux (Some r2) (r1::accu) rem
    in merge_aux None [] records

  let params = []
end

module RecordModule = MakeParserModule (RecordParser)

let wrapped_merge records =
  let raw_records = List.map RecordModule.pop_object (eval_as_list records) in
  let merged_records = RecordParser.merge raw_records in
  let result = List.map RecordModule.register merged_records in
  V_List (result)

let _ =
  add_module ((module RecordModule : Module));
  RecordModule.populate_fun ("merge", one_value_fun wrapped_merge);
  ()
