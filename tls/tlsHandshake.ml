open Types
open Modules
open ParsingEngine
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



type cipher_suite = int
type compression_method = int
type random = string
type session_id = string
type tls_extension = string

type client_hello = {
  c_version : protocol_version;
  c_random : random;
  c_session_id : session_id;
  c_cipher_suites : cipher_suite list;
  c_compression_methods : compression_method list;
  c_extensions : (tls_extension list) option
}

type server_hello = {
  s_version : protocol_version;
  s_random : random;
  s_session_id : session_id;
  s_cipher_suite : cipher_suite;
  s_compression_method : compression_method;
  s_extensions : (tls_extension list) option
}

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
  | Certificate of unit (*of X509.certificate list*)
  | ServerKeyExchange
  | CertificateRequest
  | ServerHelloDone
  | CertificateVerify
  | ClientKeyExchange
  | Finished
  | UnparsedHandshakeMsg of handshake_msg_type * string




let assert_eos pstate =
  if not (eos pstate)
  then tls_handshake_emit UnexpectedJunk None (Some (Common.hexdump (pop_string pstate))) pstate


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
  let len = extract_uint24 pstate in
  (htype, len)


let string_of_client_hello ch =
  "Client Hello:" ^
    "\n  protocol version: " ^ (string_of_protocol_version ch.c_version) ^
    "\n  random: " ^ (Common.hexdump ch.c_random) ^
    "\n  session id: " ^ (Common.hexdump ch.c_session_id) ^
    "\n  cipher suites: " ^ (String.concat ", " (List.map (Common.hexdump_int 4) ch.c_cipher_suites)) ^
    "\n  compression methods: " ^ (String.concat ", " (List.map (Common.hexdump_int 2) ch.c_compression_methods)) ^
    (* Extensions ... *)
    "\n"

let string_of_server_hello sh =
  "Server Hello:" ^
    "\n  protocol version: " ^ (string_of_protocol_version sh.s_version) ^
    "\n  random: " ^ (Common.hexdump sh.s_random) ^
    "\n  session id: " ^ (Common.hexdump sh.s_session_id) ^
    "\n  cipher suite: " ^ (Common.hexdump_int 4 sh.s_cipher_suite) ^
    "\n  compression method: " ^ (Common.hexdump_int 2 sh.s_compression_method) ^
    (* Extensions ... *)
    "\n"


let parse_hello_extensions parse_exts pstate =
  if eos pstate then None else begin
    if not parse_exts then begin
      tls_handshake_emit ExtensionsIgnored None None pstate;
      ignore (pop_string pstate);
      None
    end else
      let new_pstate = go_down_on_left_portion pstate "Extensions" in
      try
        (* TODO *)
	Some (extract_list "Extensions" extract_uint16
		(extract_variable_length_string "Extension" extract_uint16) new_pstate)
      with OutOfBounds _ ->
	tls_handshake_emit InvalidExtensions None None pstate;
	None
  end 

let parse_client_hello parse_exts pstate =
  let maj = pop_byte pstate in
  let min = pop_byte pstate in
  let random = extract_string "Random" 32 pstate in
  let session_id = extract_variable_length_string "Session id" pop_byte pstate in
  let cipher_suites = extract_list "Cipher suites" extract_uint16 extract_uint16 pstate in
  let compression_methods = extract_list "Compression methods" pop_byte pop_byte pstate in
  let extensions = parse_hello_extensions parse_exts pstate in
  ClientHello { c_version = {major = maj; minor = min};
		c_random = random;
		c_session_id = session_id;
		c_cipher_suites = cipher_suites;
		c_compression_methods = compression_methods;
		c_extensions = extensions }

let parse_server_hello parse_exts pstate =
  let maj = pop_byte pstate in
  let min = pop_byte pstate in
  let random = extract_string "Random" 32 pstate in
  let session_id = extract_variable_length_string "Session id" pop_byte pstate in
  let cipher_suite = extract_uint16 pstate in
  let compression_method = pop_byte pstate in
  let extensions = parse_hello_extensions parse_exts pstate in
  ServerHello { s_version = {major = maj; minor = min};
		s_random = random;
		s_session_id = session_id;
		s_cipher_suite = cipher_suite;
		s_compression_method = compression_method;
		s_extensions = extensions }

(*
let asn1_opts = { Asn1.type_repr = Asn1.NoType; Asn1.data_repr = Asn1.NoData;
		  Asn1.resolver = None; Asn1.indent_output = false }

let parse_one_certificate pstate =
  let s = extract_variable_length_string "Certificate" extract_uint24 pstate in
  let res = Asn1Constraints.constrained_parse (X509.certificate_constraint X509.object_directory) asn1_pstate in
  if not (Asn1.Engine.eos asn1_pstate) then emit UnexpectedJunk ParsingEngine.s_benign pstate;
  res

let parse_certificates pstate =
  try
    Certificate (extract_list "Certificates" extract_uint24 (parse_one_certificate) pstate)
  with
    | ParsingEngine.OutOfBounds s ->
      emit (ASN1ParsingError ("Out of bounds in " ^ s)) ParsingEngine.s_speclightlyviolated pstate;
      UnparsedHandshakeMsg (H_Certificate, "")
   | Asn1.Engine.ParsingError (e, s, p) ->
      emit (ASN1ParsingError (Asn1.Engine.string_of_exception e s p)) ParsingEngine.s_speclightlyviolated pstate;
      UnparsedHandshakeMsg (H_Certificate, "")
*)


let string_of_handshake_msg = function
  | HelloRequest -> "Hello Request"
  | ClientHello ch -> string_of_client_hello ch
  | ServerHello sh -> string_of_server_hello sh
  | Certificate certs -> "Certificates"
(*    "Certificates:\n" ^
      (String.concat "\n" (List.map (X509.string_of_certificate true "  " (Some X509.name_directory)) certs)) *)
  | ServerKeyExchange -> "Server Key Exchange"
  | CertificateRequest -> "Certificate Request"
  | ServerHelloDone -> "Server Hello Done"
  | CertificateVerify -> "Certificate Verify"
  | ClientKeyExchange -> "Client Key Exchange"
  | Finished -> "Finished"
  | UnparsedHandshakeMsg (htype, s) ->
    (string_of_handshake_msg_type htype) ^ " (len=" ^
      (string_of_int (String.length s)) ^ "): " ^
      (Common.hexdump s)

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

let parse_handshake parse_exts htype pstate =
  let res = match htype with
    | H_HelloRequest -> HelloRequest
    | H_ClientHello -> parse_client_hello parse_exts pstate
    | H_ServerHello -> parse_server_hello parse_exts pstate
 (*   | H_Certificate -> parse_certificates pstate *)
    | H_Certificate
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

  let parse_extensions = ref true

  let mk_ehf () = default_error_handling_function !tolerance !minDisplay

  let parse pstate =
    let (htype, len) = extract_handshake_header pstate in
    let new_pstate = go_down pstate (string_of_handshake_msg_type htype) len in
    parse_handshake !parse_extensions htype new_pstate

  let dump handshake = raise NotImplemented

  let enrich handshake dict =
    Hashtbl.replace dict "message_type" (V_String (extract_handshake_msg_type handshake));
    match handshake with
      | ClientHello ch ->
	Hashtbl.replace dict "ch_version" (V_String (string_of_protocol_version ch.c_version));
	Hashtbl.replace dict "random" (V_BinaryString ch.c_random);
	Hashtbl.replace dict "session_id" (V_BinaryString ch.c_session_id);
	Hashtbl.replace dict "ciphersuites"
	  (V_List (List.map (fun x -> V_Int x) ch.c_cipher_suites));
	Hashtbl.replace dict "compression_methods"
	  (V_List (List.map (fun x -> V_Int x) ch.c_compression_methods));
	()  (* TODO: Extensions *)
      | ServerHello sh ->
	Hashtbl.replace dict "sh_version" (V_String (string_of_protocol_version sh.s_version));
	Hashtbl.replace dict "random" (V_BinaryString sh.s_random);
	Hashtbl.replace dict "session_id" (V_BinaryString sh.s_session_id);
	Hashtbl.replace dict "ciphersuite" (V_Int sh.s_cipher_suite);
	Hashtbl.replace dict "compression_method" (V_Int sh.s_compression_method);
	()  (* TODO: Extensions *)
(*      | Certificate certs ->
	let certs = List.map X509Module.X509Module.register certs in
	Hashtbl.replace dict "certificates" (V_List certs)*)
      | _ -> ()

  let update dict = raise NotImplemented

  let to_string = string_of_handshake_msg

  let params = [
    param_from_bool_ref "parse_extensions" parse_extensions;
  ]
end

module HandshakeModule = MakeParserModule (HandshakeParser)

let _ =
  add_module ((module HandshakeModule : Module));
  ()
