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


type client_hello = (string, value) Hashtbl.t
type server_hello = (string, value) Hashtbl.t
type handshake_msg_type =
  | H_HelloRequest
  | H_ClientHello
  | H_ServerHello
  | H_Certificate
  | H_ServerKeyExchange
  | H_CertificateRequest
  | H_ServerHelloDone
  | H_CertificateVerify
  | H_ClientKeyExchange
  | H_Finished
  | H_Unknown of int

type handshake_msg =
  | HelloRequest
  | ClientHello of client_hello
  | ServerHello of server_hello
  | Certificate of (string list, X509.certificate list) alternative
  | ServerKeyExchange
  | CertificateRequest
  | ServerHelloDone
  | CertificateVerify
  | ClientKeyExchange
  | Finished
  | UnparsedHandshakeMsg of handshake_msg_type * string




let assert_eos pstate =
  if not (eos pstate)
  then tls_handshake_emit UnexpectedJunk None (Some (hexdump (pop_string pstate))) pstate


let handshake_msg_type_of_int = function
  |  0 -> H_HelloRequest
  |  1 -> H_ClientHello
  |  2 -> H_ServerHello
  | 11 -> H_Certificate
  | 12 -> H_ServerKeyExchange
  | 13 -> H_CertificateRequest
  | 14 -> H_ServerHelloDone
  | 15 -> H_CertificateVerify
  | 16 -> H_ClientKeyExchange
  | 20 -> H_Finished
  |  x -> H_Unknown x

let string_of_handshake_msg_type = function
  | H_HelloRequest -> "Hello Request"
  | H_ClientHello -> "Client Hello"
  | H_ServerHello -> "Server Hello"
  | H_Certificate -> "Certificate"
  | H_ServerKeyExchange -> "Server Key Exchange"
  | H_CertificateRequest -> "Certificate Request"
  | H_ServerHelloDone -> "Server Hello Done"
  | H_CertificateVerify -> "Certificate Verify"
  | H_ClientKeyExchange -> "Client Key Exchange"
  | H_Finished -> "Finished"
  | H_Unknown x -> "Unknown handshake message " ^ (string_of_int x)

let extract_handshake_msg_type = function
  | HelloRequest -> "Hello Request"
  | ClientHello _ -> "Client Hello"
  | ServerHello _ -> "Server Hello"
  | Certificate _ -> "Certificate"
  | ServerKeyExchange -> "Server Key Exchange"
  | CertificateRequest -> "Certificate Request"
  | ServerHelloDone -> "Server Hello Done"
  | CertificateVerify -> "Certificate Verify"
  | ClientKeyExchange -> "Client Key Exchange"
  | Finished -> "Finished"
  | UnparsedHandshakeMsg (x, _) -> string_of_handshake_msg_type x

let extract_handshake_header pstate =
  let htype = handshake_msg_type_of_int (pop_byte pstate) in
  let len = pop_uint24 pstate in
  (htype, len)


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



let client_hello_description = [
  ("version", parse_protocol_version, dumpv_uint16);
  ("random", parse_bin_string 32, eval_as_string);
  ("session_id", parse_varlen_bin_string pop_byte, dump_varlen_string dump_uint8);
  ("cipher_suites", lift_list (pop_varlen_list "Cipher suites" pop_uint16 parse_uint16), dump_varlen_list dump_uint16 dumpv_uint16);
  ("compression_methods", lift_list (pop_varlen_list "Compression methods" pop_byte parse_uint8), dump_varlen_list dump_uint8 dumpv_uint8);
  ("extensions", parse_hello_extensions, dump_hello_extensions)
]

let server_hello_description = [
  ("version", parse_protocol_version, dumpv_uint16);
  ("random", parse_bin_string 32, eval_as_string);
  ("session_id", parse_varlen_bin_string pop_byte, eval_as_string);
  ("cipher_suite", parse_uint16, dumpv_uint16);
  ("compression_methods", parse_uint8, dumpv_uint8);
  ("extensions", parse_hello_extensions, dump_hello_extension)
]



let parse_client_hello pstate = BinaryRecord.parse client_hello_description pstate
let string_of_client_hello ch =
  let content =
    [ "protocol version: " ^ (protocol_version_string_of_int (eval_as_int (ch --> "version")));
      "random: " ^ (hexdump (eval_as_string (ch --> "random")));
      "session id: " ^ (hexdump (eval_as_string (ch --> "session_id")));
      "cipher suites: " ^ (String.concat ", " (List.map (fun x -> hexdump_int 4 (eval_as_int x)) (eval_as_list (ch --> "cipher_suites"))));
      "compression methods: " ^ (String.concat ", " (List.map (fun x -> hexdump_int 2 (eval_as_int x)) (eval_as_list (ch --> "compression_methods")))) ]
    (* TODO: Extensions ... *)
  in PrinterLib._string_of_strlist (Some "Client Hello") indent_only content


let parse_server_hello pstate = BinaryRecord.parse server_hello_description pstate
let string_of_server_hello sh =
  let content =
    [ "protocol version: " ^ (protocol_version_string_of_int (eval_as_int (sh --> "version")));
      "random: " ^ (hexdump (eval_as_string (sh --> "random")));
      "session id: " ^ (hexdump (eval_as_string (sh --> "session_id")));
      "cipher suites: " ^ (hexdump_int 4 (eval_as_int (sh --> "cipher_suite")));
      "compression methods: " ^ (hexdump_int 2 (eval_as_int (sh --> "compression_methods"))) ]
    (* TODO: Extensions ... *)
  in PrinterLib._string_of_strlist (Some "Server Hello") indent_only content



let parse_one_certificate pstate =
  let len = pop_uint24 pstate in
  let new_pstate = go_down pstate "Certificate" len in
  let res = Asn1Constraints.constrained_parse X509.certificate_constraint new_pstate in
  assert_eos new_pstate;
  res

let parse_certificate_msg pstate =
  if (!parse_certificates)
  then Certificate (Right (pop_varlen_list "Certificates" pop_uint24 (parse_one_certificate) pstate))
  else Certificate (Left (pop_varlen_list "Certificates" pop_uint24 (pop_varlen_string pop_uint24) pstate))


let string_of_handshake_msg = function
  | HelloRequest -> ["Hello Request"]
  | ClientHello ch -> string_of_client_hello ch
  | ServerHello sh -> string_of_server_hello sh
  | Certificate (Left raw_certs) ->
    PrinterLib._string_of_strlist (Some "Certificates") indent_only (List.map hexdump raw_certs)
  | Certificate (Right certs) ->
    let certs_str = List.flatten (List.map (X509.string_of_certificate (Some "Certificate")) certs) in
    PrinterLib._string_of_strlist (Some "Certificates") indent_only certs_str
  | ServerKeyExchange -> ["Server Key Exchange"]
  | CertificateRequest -> ["Certificate Request"]
  | ServerHelloDone -> ["Server Hello Done"]
  | CertificateVerify -> ["Certificate Verify"]
  | ClientKeyExchange -> ["Client Key Exchange"]
  | Finished -> ["Finished"]
  | UnparsedHandshakeMsg (htype, s) ->
    let hdr = (string_of_handshake_msg_type htype) ^ " (len=" ^ (string_of_int (String.length s)) ^ ")" in
    PrinterLib._string_of_strlist (Some hdr) indent_only [hexdump s]


let type_of_handshake_msg = function
  | HelloRequest -> H_HelloRequest
  | ClientHello _ ->  H_ClientHello
  | ServerHello _ -> H_ServerHello
  | Certificate _ -> H_Certificate
  | ServerKeyExchange -> H_ServerKeyExchange
  | CertificateRequest -> H_CertificateRequest
  | ServerHelloDone -> H_ServerHelloDone
  | CertificateVerify -> H_CertificateVerify
  | ClientKeyExchange -> H_ClientKeyExchange
  | Finished -> H_Finished
  | UnparsedHandshakeMsg (htype, _) -> htype

let parse_handshake htype pstate =
  let res = match htype with
    | H_HelloRequest -> HelloRequest
    | H_ClientHello -> ClientHello (parse_client_hello pstate)
    | H_ServerHello -> ServerHello (parse_server_hello pstate)
    | H_Certificate -> parse_certificate_msg pstate
    | H_ServerKeyExchange
    | H_CertificateRequest -> UnparsedHandshakeMsg (htype, pop_string pstate)
    | H_ServerHelloDone -> ServerHelloDone
    | H_CertificateVerify
    | H_ClientKeyExchange
    | H_Finished -> UnparsedHandshakeMsg (htype, pop_string pstate)
    | H_Unknown x ->
      tls_handshake_emit UnexpectedHandshakeMsgType None (Some (string_of_int x)) pstate;
      UnparsedHandshakeMsg (htype, pop_string pstate)
  in
  assert_eos pstate;
  res


module HandshakeParser = struct
  let name = "handshake"
  type t = handshake_msg

  let parse pstate =
    let (htype, len) = extract_handshake_header pstate in
    let new_pstate = go_down pstate (string_of_handshake_msg_type htype) len in
    parse_handshake htype new_pstate

  let dump handshake =
    (* TODO! *)
    let htype_dump, content_dump = match handshake with
      | ClientHello ch -> "\x01", BinaryRecord.dump client_hello_description ch
      | ServerHello sh -> "\x01", BinaryRecord.dump server_hello_description sh
      | _ -> raise (NotImplemented "handshake.dump")
    in
    htype_dump ^ (dump_uint24 (String.length content_dump)) ^ content_dump
    
  let enrich handshake dict =
    Hashtbl.replace dict "message_type" (V_String (extract_handshake_msg_type handshake));
    match handshake with
      | ClientHello ch -> BinaryRecord.enrich client_hello_description ch dict
      | ServerHello sh -> BinaryRecord.enrich server_hello_description sh dict
      | Certificate (Left raw_certs) ->
	let strs = List.map (fun x -> V_BinaryString x) raw_certs in
	Hashtbl.replace dict "certificates" (V_List strs)
      | Certificate (Right certs) ->
	let cert_objs = List.map X509.X509Module.register certs in
	Hashtbl.replace dict "certificates" (V_List cert_objs)
      | _ -> ()

  let update dict =
    match hash_find dict "message_type" with
      | V_String ("Client Hello") | V_Int 1 -> ClientHello (BinaryRecord.update client_hello_description dict)
      | V_String ("Server Hello") | V_Int 2 -> ServerHello (BinaryRecord.update server_hello_description dict)
      | _ -> raise (NotImplemented "handshake.update")

  let to_string = string_of_handshake_msg

  let params = []
  let functions = []
end

module HandshakeModule = MakeParserModule (HandshakeParser)

let _ = add_object_module ((module HandshakeModule : ObjectModule))
