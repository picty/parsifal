open Common
open Types
open Printer
open Modules
open ParsingEngine
open BinaryRecord
open TlsCommon


type tls_handshake_errors =
  | UnexpectedHandshakeMsgType
  | UnexpectedJunk
  | ExtensionsIgnored
  | InvalidExtensions

let tls_handshake_errors_strings = [|
  (UnexpectedHandshakeMsgType, s_benign, "Unexpected handshake message type");
  (UnexpectedJunk, s_idempotencebreaker, "Unexpected junk in handshake message");
  (ExtensionsIgnored, s_idempotencebreaker, "Extensions were present, and not parsed");
  (InvalidExtensions, s_idempotencebreaker, "Invalid extensions");
|]

let tls_handshake_emit = register_module_errors_and_make_emit_function "tlsHandshake" tls_handshake_errors_strings


(* The params are declared here but are associated to the Tls module *)
let parse_extensions = ref true
let parse_certificates = ref false (* TODO: Is this the good default? *)



(* Handshake message type *)

type handshake_msg_type = int

let message_type_string_of_int = function
  |  0 -> "Hello Request"
  |  1 -> "Client Hello"
  |  2 -> "Server Hello"
  | 11 -> "Certificate"
  | 12 -> "Server Key Exchange"
  | 13 -> "Certificate Request"
  | 14 -> "Server Hello Done"
  | 15 -> "Certificate Verify"
  | 16 -> "Client Key Exchange"
  | 20 -> "Finished"
  |  x -> "Unknown handshake message type " ^ (string_of_int x)

let message_type_int_of_string = function
  | "Hello Request" -> 0
  | "Client Hello" -> 1
  | "Server Hello" -> 2
  | "Certificate" -> 11
  | "Server Key Exchange" -> 12
  | "Certificate Request" -> 13
  | "Server Hello Done" -> 14
  | "Certificate Verify" -> 15
  | "Client Key Exchange" -> 16
  | "Finished" -> 20
  | s -> int_of_string s

let check_message_type pstate = function
  | 0 | 1 | 2 | 11 | 12 | 13 | 14 | 15 | 16 | 20 -> ()
  | x -> tls_handshake_emit UnexpectedHandshakeMsgType None (Some (string_of_int x)) pstate

let pop_message_type pstate =
  let hmt = pop_byte pstate in
  check_message_type pstate hmt;
  hmt

let _make_message_type = function
  | V_Int i
  | V_Enumerated (i, _) -> i
  | V_String s -> message_type_int_of_string s
  | _ -> raise (ContentError "Invalid handshake message type value")

let make_message_type v = V_Enumerated (_make_message_type v, message_type_string_of_int)



let assert_eos pstate =
  if not (eos pstate)
  then tls_handshake_emit UnexpectedJunk None (Some (hexdump (pop_string pstate))) pstate


let extract_handshake_header pstate =
  let htype = pop_message_type pstate in
  let len = pop_uint24 pstate in
  (htype, len)



(* Hello *)

type random = string
type session_id = string
type tls_extension = int * string

let parse_hello_extension pstate =
  let id = parse_uint16 pstate in
  let content = parse_varlen_string pop_uint16 pstate in
  V_List [id; content]

let parse_hello_extensions pstate =
  if eos pstate then V_Unit else begin
    if not (!parse_extensions) then begin
      tls_handshake_emit ExtensionsIgnored None None pstate;
      ignore (pop_string pstate);
      V_Unit
    end else
      let new_pstate = go_down_on_left_portion pstate "Extension container" in
      try
	V_List (pop_varlen_list "Extensions" pop_uint16 parse_hello_extension new_pstate)
      with OutOfBounds _ ->
	tls_handshake_emit InvalidExtensions None None pstate;
	V_Unit
  end

let dump_hello_extension = function
  | V_List [id; content] -> (dumpv_uint16 id) ^ (dump_varlen_string dump_uint16 content)
  | _ -> raise (ContentError "Invalid hello extension value")

let dump_hello_extensions = function
  | V_Unit -> ""
  | v -> dump_varlen_list dump_uint16 dump_hello_extension v


let client_hello_description = BinaryRecord.mk_desc [
  ("version", parse_protocol_version, dumpv_uint16, None);
  ("random", parse_bin_string 32, eval_as_string, raw_hex);
  ("session_id", parse_varlen_bin_string pop_byte, dump_varlen_string dump_uint8, raw_hex);
  ("cipher_suites", lift_list (pop_varlen_list "Cipher suites" pop_uint16 parse_uint16),
                    dump_varlen_list dump_uint16 dumpv_uint16, hex_int_list 4);
  ("compression_methods", lift_list (pop_varlen_list "Compression methods" pop_byte parse_uint8),
                          dump_varlen_list dump_uint8 dumpv_uint8, hex_int_list 2);
  ("extensions", parse_hello_extensions, dump_hello_extensions, None)
]

let server_hello_description = BinaryRecord.mk_desc [
  ("version", parse_protocol_version, dumpv_uint16, None);
  ("random", parse_bin_string 32, eval_as_string, raw_hex);
  ("session_id", parse_varlen_bin_string pop_byte, eval_as_string, raw_hex);
  ("cipher_suite", parse_uint16, dumpv_uint16, hex_int 4);
  ("compression_method", parse_uint8, dumpv_uint8, hex_int 2);
  ("extensions", parse_hello_extensions, dump_hello_extension, None)
]


let parse_client_hello pstate = V_Dict (BinaryRecord.parse client_hello_description pstate)
let string_of_client_hello ch = BinaryRecord.to_string (Some "Client Hello") client_hello_description ch

let parse_server_hello pstate = V_Dict (BinaryRecord.parse server_hello_description pstate)
let string_of_server_hello sh = BinaryRecord.to_string (Some "Server Hello") server_hello_description sh



(* Certificate *)

let parse_one_certificate pstate =
  let len = pop_uint24 pstate in
  let new_pstate = go_down pstate "Certificate" len in
  let res = Asn1Constraints.constrained_parse X509.certificate_constraint new_pstate in
  assert_eos new_pstate;
  X509.X509Module.register res

let parse_certificate_msg pstate =
  if (!parse_certificates)
  then V_List (pop_varlen_list "Certificates" pop_uint24 (parse_one_certificate) pstate)
  else V_List (pop_varlen_list "Certificates" pop_uint24 (parse_varlen_bin_string pop_uint24) pstate)

let string_of_certificate = function
  | V_BinaryString s -> [hexdump s]
  | V_Object ("x509", _, _) as o -> X509.string_of_certificate (Some "Certificate") (X509.X509Module.pop_object o)
  | _ -> raise (ContentError ("Invalid certificate value"))


(* General handshake messages *)


type handshake_msg = handshake_msg_type * value

let string_of_handshake_msg (msg_type, content) =
  let msg_str = message_type_string_of_int msg_type in
  match msg_type, content with
    | _, V_Unit -> [msg_str]
    | _, V_BinaryString s -> [PrinterLib._single_line (Some msg_str) (hexdump s)]
    | 1, V_Dict d -> string_of_client_hello d
    | 2, V_Dict d -> string_of_server_hello d
    | 11, V_List l ->
      let certs_str = List.flatten (List.map string_of_certificate l) in
      PrinterLib._string_of_strlist (Some "Certificates") indent_only certs_str
    | _ -> raise (ContentError ("Invalid Handshake value"))

let parse_handshake htype pstate =
  let res = match htype with
    | 1 -> parse_client_hello pstate
    | 2 -> parse_server_hello pstate
    | 11 -> parse_certificate_msg pstate
    | 0 | 14 -> V_Unit
    | _ -> V_BinaryString (pop_string pstate)
  in
  assert_eos pstate;
  htype, res


module HandshakeParser = struct
  let name = "handshake"
  type t = handshake_msg

  let parse pstate =
    let (htype, len) = extract_handshake_header pstate in
    let new_pstate = go_down pstate (message_type_string_of_int htype) len in
    parse_handshake htype new_pstate

  let dump (msg_type, content) =
    let content_dump = match msg_type, content with
      | _, V_Unit -> ""
      | _, V_BinaryString s -> s
      | 0x01, V_Dict ch -> BinaryRecord.dump client_hello_description ch
      | 0x02, V_Dict sh -> BinaryRecord.dump server_hello_description sh
      | 0x11, V_List certs -> raise (NotImplemented "handshake.dump")
      | _ -> raise (NotImplemented "handshake.dump")
    in
    (dump_uint8 msg_type) ^ (dump_uint24 (String.length content_dump)) ^ content_dump
    
  let enrich (msg_type, content) dict =
    Hashtbl.replace dict "message_type" (V_Enumerated (msg_type, message_type_string_of_int));
    match msg_type, content with
      | _, V_Unit -> ()
      | _, (V_BinaryString _ as s) -> Hashtbl.replace dict "content" s
      | 0x01, V_Dict ch -> BinaryRecord.enrich client_hello_description ch dict
      | 0x02, V_Dict sh -> BinaryRecord.enrich server_hello_description sh dict
      | 0x0b, (V_List _ as l) -> Hashtbl.replace dict "certificates" l
      | _ -> raise (NotImplemented "handshake.enrich")

  let update dict =
    match hash_find dict "message_type" with
      | V_String ("Client Hello") | V_Int 1  ->  1, V_Dict (BinaryRecord.update client_hello_description dict)
      | V_String ("Server Hello") | V_Int 2  ->  2, V_Dict (BinaryRecord.update server_hello_description dict)
      | V_String ("Certificate")  | V_Int 11 -> 11, hash_find dict "certificates"
      | _ -> raise (NotImplemented "handshake.update")

  let to_string = string_of_handshake_msg

  let params = []
  let functions = []
end

module HandshakeModule = MakeParserModule (HandshakeParser)

let _ = add_object_module ((module HandshakeModule : ObjectModule))
