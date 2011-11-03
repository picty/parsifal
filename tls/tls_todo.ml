(*

(* Handshake *)

type cipher_suite = int

type compression_method =
  | CM_Null
  | CM_Unknown of int

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
  | Certificate of X509.certificate list
  | ServerKeyExchange
  | CertificateRequest
  | ServerHelloDone
  | CertificateVerify
  | ClientKeyExchange
  | Finished
  | UnparsedHandshakeMsg of handshake_msg_type * string






  type parsing_error =
    | InternalMayhem
    | UnexpectedJunk
    | UnexpectedContentType of int
    | UnexpectedChangeCipherSpecValue of int
    | UnexpectedAlertLevel of int
    | UnexpectedAlertType of int
    | UnexpectedHandshakeMsgType of int
    | ASN1ParsingError of string
    | NotImplemented of string



(* Trivial parsing functions *)

let assert_eos pstate =
  if not (eos pstate) then emit UnexpectedJunk ParsingEngine.s_benign pstate



(* ChangeCipherSpec *)

let parse_change_cipher_spec pstate =
  let v = pop_byte pstate in
  if v <> 1 then emit (UnexpectedChangeCipherSpecValue v) ParsingEngine.s_benign pstate;
  assert_eos pstate;
  ChangeCipherSpec





let string_of_compression_method = function
  | CM_Null -> "Null"
  | CM_Unknown x -> Common.hexdump_int 2 x

let compression_method_of_int = function
  | 0 -> CM_Null
  | x -> CM_Unknown x

let int_of_compression_method = function
  | CM_Null -> 0
  | CM_Unknown x -> x

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

let handshake_msg_type_of_int pstate = function
  | 0 -> H_HelloRequest
  | 1 -> H_ClientHello
  | 2 -> H_ServerHello
  | 11 -> H_Certificate
  | 12 -> H_ServerKeyExchange
  | 13 -> H_CertificateRequest
  | 14 -> H_ServerHelloDone
  | 15 -> H_CertificateVerify
  | 16 -> H_ClientKeyExchange
  | 20 -> H_Finished
  | x ->
    emit (UnexpectedHandshakeMsgType x) ParsingEngine.s_benign pstate;
    H_Unknown x

let extract_handshake_header pstate =
  let htype = handshake_msg_type_of_int pstate (pop_byte pstate) in
  let len = extract_uint24 pstate in
  (htype, len)


let string_of_client_hello ch =
  "Client Hello:" ^
    "\n  protocol version: " ^ (string_of_protocol_version ch.c_version) ^
    "\n  random: " ^ (Common.hexdump ch.c_random) ^
    "\n  session id: " ^ (Common.hexdump ch.c_session_id) ^
    "\n  cipher suites: " ^ (String.concat ", " (List.map (Common.hexdump_int 4) ch.c_cipher_suites)) ^
    "\n  compression methods: " ^ (String.concat ", " (List.map string_of_compression_method ch.c_compression_methods)) ^
    (* Extensions ... *)
    "\n"

let string_of_server_hello sh =
  "Server Hello:" ^
    "\n  protocol version: " ^ (string_of_protocol_version sh.s_version) ^
    "\n  random: " ^ (Common.hexdump sh.s_random) ^
    "\n  session id: " ^ (Common.hexdump sh.s_session_id) ^
    "\n  cipher suite: " ^ (Common.hexdump_int 4 sh.s_cipher_suite) ^
    "\n  compression method: " ^ (string_of_compression_method sh.s_compression_method) ^
    (* Extensions ... *)
    "\n"

let parse_hello_extensions parse_exts pstate =
  if eos pstate then None else begin
    if not parse_exts then begin
    ignore (pop_string pstate);
    None
  end else
      let new_pstate = pstate_of_pstate pstate (pop_string pstate) in
      try
        (* TODO *)
	Some (extract_list "Extensions" extract_uint16
		(extract_variable_length_string "Extension" extract_uint16) new_pstate)
      with ParsingEngine.OutOfBounds _ ->
	emit UnexpectedJunk ParsingEngine.s_idempotencebreaker pstate;
	None
  end 

let parse_client_hello parse_exts pstate =
  let maj = pop_byte pstate in
  let min = pop_byte pstate in
  let random = extract_string "Random" 32 pstate in
  let session_id = extract_variable_length_string "Session id" pop_byte pstate in
  let cipher_suites = extract_list "Cipher suites" extract_uint16 extract_uint16 pstate in
  let compression_methods = List.map compression_method_of_int
    (extract_list "Compression methods" pop_byte pop_byte pstate) in
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
  let compression_method = compression_method_of_int (pop_byte pstate) in
  let extensions = parse_hello_extensions parse_exts pstate in
  ServerHello { s_version = {major = maj; minor = min};
		s_random = random;
		s_session_id = session_id;
		s_cipher_suite = cipher_suite;
		s_compression_method = compression_method;
		s_extensions = extensions }


let asn1_opts = { Asn1.type_repr = Asn1.NoType; Asn1.data_repr = Asn1.NoData;
		  Asn1.resolver = None; Asn1.indent_output = false }

let parse_one_certificate pstate =
  let s = extract_variable_length_string "Certificate" extract_uint24 pstate in
  let asn1_pstate = Asn1.Engine.pstate_of_string (string_of_pstate pstate) s in
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
    
      


let string_of_handshake_msg = function
  | HelloRequest -> "Hello Request"
  | ClientHello ch -> string_of_client_hello ch
  | ServerHello sh -> string_of_server_hello sh
  | Certificate certs ->
    "Certificates:\n" ^
      (String.concat "\n" (List.map (X509.string_of_certificate true "  " (Some X509.name_directory)) certs))
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

let parse_handshake_content parse_exts htype pstate =
  match htype with
    | H_HelloRequest ->
      assert_eos pstate;
      HelloRequest
    | H_ClientHello -> parse_client_hello parse_exts pstate
    | H_ServerHello -> parse_server_hello parse_exts pstate
    | H_Certificate -> parse_certificates pstate
    | H_ServerKeyExchange
    | H_CertificateRequest -> UnparsedHandshakeMsg (htype, pop_string pstate)
    | H_ServerHelloDone ->
      assert_eos pstate;
      ServerHelloDone
    | H_CertificateVerify
    | H_ClientKeyExchange
    | H_Finished
    | H_Unknown _ -> UnparsedHandshakeMsg (htype, pop_string pstate)

let parse_handshake parse_exts pstate =
  let rec aux () =
    if not (eos pstate) then begin
      let (htype, len) = extract_handshake_header pstate in
      go_down pstate (string_of_handshake_msg_type htype) len;
      let msg = parse_handshake_content parse_exts htype pstate in
      go_up pstate;
      msg::(aux ())
    end else []
  in Handshake (aux())

*)
