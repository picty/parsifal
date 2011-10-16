open X509Directory


(* Alert *)

type alert_level =
  | AL_Warning
  | AL_Fatal
  | AL_Unknown of int

type alert_type =
  | CloseNotify
  | UnexpectedMessage
  | BadRecordMac
(* TODO: Should not be used in TLSv1.* ; add checks for the alert it is OK to send in certain versions *)
  | DecryptionFailed
  | RecordOverflow
  | DecompressionFailure
  | HandshakeFailure
  | NoCertificate
  | BadCertificate
  | UnsupportedCertificate
  | CertificateRevoked
  | CertificateExpired
  | CertificateUnknown
  | IllegalParameter
  | UnknownCA
  | AccessDenied
  | DecodeError
  | DecryptError
(* TODO: Should not be used in TLSv1.* ; add checks for the alert it is OK to send in certain versions *)
  | ExportRestriction
  | ProtocolVersion
  | InsufficientSecurity
  | InternalError
  | UserCanceled
  | NoRenegotiation
  | UnsupportedExtension
  | UnknownAlertType of int


(* Handshake *)

type protocol_version = { major : int; minor : int }

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


(* Record *)

type content_type =
  | CT_ChangeCipherSpec
  | CT_Alert
  | CT_Handshake
  | CT_ApplicationData
  | CT_Unknown of int

type record_content =
  | ChangeCipherSpec
  | Alert of alert_level * alert_type
  | Handshake of handshake_msg
  | ApplicationData of string
  | UnparsedRecord of content_type * string

type record = {
  version : protocol_version;
  content : record_content
}




module TlsEngineParams = struct
  type parsing_error =
    | InternalMayhem
    | OutOfBounds of string
    | UnexpectedJunk
    | UnexpectedContentType of int
    | UnexpectedChangeCipherSpecValue of int
    | UnexpectedAlertLevel of int
    | UnexpectedAlertType of int
    | UnexpectedHandshakeMsgType of int
    | ASN1ParsingError of Asn1.Asn1EngineParams.parsing_error
    | NotImplemented of string

  let out_of_bounds_error s = OutOfBounds s

  let string_of_perror = function
    | InternalMayhem -> "Internal mayhem"
    | OutOfBounds s -> "Out of bounds (" ^ s ^ ")"
    | UnexpectedJunk -> "Unexpected junk"
    | UnexpectedContentType x -> "Unknown content type " ^ (string_of_int x)
    | UnexpectedChangeCipherSpecValue x -> "Unknown ChangeCipherSpec value " ^ (string_of_int x)
    | UnexpectedAlertLevel x -> "Unknown alert level " ^ (string_of_int x)
    | UnexpectedAlertType x -> "Unknown alert type " ^ (string_of_int x)
    | UnexpectedHandshakeMsgType x -> "Unknown handshake message type " ^ (string_of_int x)
    | ASN1ParsingError e -> "ASN1 parsing error (" ^ (Asn1.Asn1EngineParams.string_of_perror e) ^ ")"
    | NotImplemented s -> "Not implemented (" ^ s ^  ")"

  type severity =
    | S_OK
    | S_Benign
    | S_Fatal

  let fatal_severity = S_Fatal

  let string_of_severity = function
    | S_OK -> "OK"
    | S_Benign -> "Benign"
    | S_Fatal -> "Fatal"

  let int_of_severity = function
    | S_OK -> 0
    | S_Benign -> 1
    | S_Fatal -> 2

  let compare_severity x y =
    compare (int_of_severity x) (int_of_severity y)
end

open TlsEngineParams;;
module Engine = ParsingEngine.ParsingEngine (TlsEngineParams);;
open Engine;;



(* Trivial parsing functions *)

let extract_list name length_fun extract_fun pstate =
  let rec aux () =
    if eos pstate
    then []
    else begin
      let next = extract_fun pstate in
      next::(aux ())
    end
  in
  let len = length_fun pstate in
  go_down pstate name len;
  let res = aux () in
  go_up pstate;
  res


let assert_eos pstate =
  if not (eos pstate) then emit UnexpectedJunk S_Benign pstate



(* ChangeCipherSpec *)

let parse_change_cipher_spec pstate =
  let v = pop_byte pstate in
  if v <> 1 then emit (UnexpectedChangeCipherSpecValue v) S_Benign pstate;
  assert_eos pstate;
  ChangeCipherSpec



(* Alert *)

let string_of_alert_level = function
  | AL_Warning -> "Warning"
  | AL_Fatal -> "Fatal"
  | AL_Unknown x -> "Unknown alert level " ^ (string_of_int x)

let string_of_alert_type = function
  | CloseNotify -> "Close notify"
  | UnexpectedMessage -> "Unexpected message"
  | BadRecordMac -> "Bad record mac"
  | DecryptionFailed -> "Decryption failed"
  | RecordOverflow -> "Record overflow"
  | DecompressionFailure -> "Decompression failure"
  | HandshakeFailure -> "Handshake failure"
  | NoCertificate -> "No certificate"
  | BadCertificate -> "Bad certificate"
  | UnsupportedCertificate -> "Unsupported certificate"
  | CertificateRevoked -> "Certificate revoked"
  | CertificateExpired -> "Certificate expired"
  | CertificateUnknown -> "Certificate unknown"
  | IllegalParameter -> "Illegal parameter"
  | UnknownCA -> "Unknown CA"
  | AccessDenied -> "Access denied"
  | DecodeError -> "Decode error"
  | DecryptError -> "Decrypt error"
  | ExportRestriction -> "Export restriction"
  | ProtocolVersion -> "Protocol version"
  | InsufficientSecurity -> "Insufficient security"
  | InternalError -> "Internal error"
  | UserCanceled -> "User canceled"
  | NoRenegotiation -> "No renegotiation"
  | UnsupportedExtension -> "Unsupported extension"
  | UnknownAlertType x -> "Unknown alert type " ^ (string_of_int x)

let alert_level_of_int pstate = function
  | 1 -> AL_Warning
  | 2 -> AL_Fatal
  | x ->
    emit (UnexpectedAlertLevel x) S_Benign pstate;
    AL_Unknown x

let alert_type_of_int pstate = function
  | 0 -> CloseNotify
  | 10 -> UnexpectedMessage
  | 20 -> BadRecordMac
  | 21 -> DecryptionFailed
  | 22 -> RecordOverflow
  | 30 -> DecompressionFailure
  | 40 -> HandshakeFailure
  | 41 -> NoCertificate
  | 42 -> BadCertificate
  | 43 -> UnsupportedCertificate
  | 44 -> CertificateRevoked
  | 45 -> CertificateExpired
  | 46 -> CertificateUnknown
  | 47 -> IllegalParameter
  | 48 -> UnknownCA
  | 49 -> AccessDenied
  | 50 -> DecodeError
  | 51 -> DecryptError
  | 60 -> ExportRestriction
  | 70 -> ProtocolVersion
  | 71 -> InsufficientSecurity
  | 80 -> InternalError
  | 90 -> UserCanceled
  | 100 -> NoRenegotiation
  | 110 -> UnsupportedExtension
  | x ->
    emit (UnexpectedAlertType x) S_Benign pstate;
    UnknownAlertType x

let parse_alert pstate =
  let level = pop_byte pstate in
  let t = pop_byte pstate in
  assert_eos pstate;
  Alert (alert_level_of_int pstate level, alert_type_of_int pstate t)



(* Handshake *)

let string_of_protocol_version v = match (v.major, v.minor) with
  | 2, 0 -> "SSLv2"
  | 3, 0 -> "SSLv3"
  | 3, 1 -> "TLSv1.0"
  | 3, 2 -> "TLSv1.1"
  | 3, 3 -> "TLSv1.2"
  | maj, min -> "version" ^ (string_of_int maj) ^ "." ^ (string_of_int min)


let string_of_compression_method = function
  | CM_Null -> "Null"
  | CM_Unknown x -> Common.hexdump_int 2 x

let compression_method_of_int = function
  | 0 -> CM_Null
  | x -> CM_Unknown x


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
    emit (UnexpectedHandshakeMsgType x) S_Benign pstate;
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

let parse_client_hello pstate =
  let maj = pop_byte pstate in
  let min = pop_byte pstate in
  let random = extract_string "Random" 32 pstate in
  let session_id = extract_variable_length_string "Session id" pop_byte pstate in
  let cipher_suites = extract_list "Cipher suites" extract_uint16 extract_uint16 pstate in
  let compression_methods = List.map compression_method_of_int
    (extract_list "Compression methods" pop_byte pop_byte pstate) in
  let extensions = if eos pstate then None else begin
    (* TODO *)
    Some (extract_list "Extensions" extract_uint16
	    (extract_variable_length_string "Extension" extract_uint16) pstate)
  end in
  ClientHello { c_version = {major = maj; minor = min};
		c_random = random;
		c_session_id = session_id;
		c_cipher_suites = cipher_suites;
		c_compression_methods = compression_methods;
		c_extensions = extensions }


let string_of_server_hello sh =
  "Server Hello:" ^
    "\n  protocol version: " ^ (string_of_protocol_version sh.s_version) ^
    "\n  random: " ^ (Common.hexdump sh.s_random) ^
    "\n  session id: " ^ (Common.hexdump sh.s_session_id) ^
    "\n  cipher suite: " ^ (Common.hexdump_int 4 sh.s_cipher_suite) ^
    "\n  compression method: " ^ (string_of_compression_method sh.s_compression_method) ^
    (* Extensions ... *)
    "\n"

let parse_server_hello pstate =
  let maj = pop_byte pstate in
  let min = pop_byte pstate in
  let random = extract_string "Random" 32 pstate in
  let session_id = extract_variable_length_string "Session id" pop_byte pstate in
  let cipher_suite = extract_uint16 pstate in
  let compression_method = compression_method_of_int (pop_byte pstate) in
  let extensions = if eos pstate then None else begin
    (* TODO *)
    Some (extract_list "Extensions" extract_uint16
	    (extract_variable_length_string "Extension" extract_uint16) pstate)
  end in
  ServerHello { s_version = {major = maj; minor = min};
		s_random = random;
		s_session_id = session_id;
		s_cipher_suite = cipher_suite;
		s_compression_method = compression_method;
		s_extensions = extensions }


let asn1_opts = { Asn1.type_repr = Asn1.NoType; Asn1.data_repr = Asn1.NoData;
		  Asn1.resolver = None; Asn1.indent_output = false }

let parse_one_certificate asn1_ehf pstate =
  let s = extract_variable_length_string "Certificate" extract_uint24 pstate in
  try
    let asn1_pstate = Asn1.Engine.pstate_of_string asn1_ehf (string_of_pstate pstate) s in
    let res = Asn1Constraints.constrained_parse (X509.certificate_constraint X509.object_directory) asn1_pstate in
    if not (Asn1.Engine.eos asn1_pstate) then emit UnexpectedJunk S_Benign pstate;
    res
  with
      (* TODO: Handle things better? *)
      e -> raise e

let parse_certificates asn1_ehf pstate =
  Certificate (extract_list "Certificates" extract_uint24 (parse_one_certificate asn1_ehf) pstate)


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

let parse_handshake asn1_ehf pstate =
  let (htype, len) = extract_handshake_header pstate in
  go_down pstate (string_of_handshake_msg_type htype) len;
  let content = match htype with
    | H_HelloRequest ->
      assert_eos pstate;
      HelloRequest
    | H_ClientHello -> parse_client_hello pstate
    | H_ServerHello -> parse_server_hello pstate
    | H_Certificate -> parse_certificates asn1_ehf pstate
    | H_ServerKeyExchange
    | H_CertificateRequest -> UnparsedHandshakeMsg (htype, pop_string pstate)
    | H_ServerHelloDone ->
      assert_eos pstate;
      ServerHelloDone
    | H_CertificateVerify
    | H_ClientKeyExchange
    | H_Finished
    | H_Unknown _ -> UnparsedHandshakeMsg (htype, pop_string pstate)
  in
  go_up pstate;
  Handshake (content)




(* Record *)

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
    emit (UnexpectedContentType x) S_Benign pstate;
    CT_Unknown x

let extract_record_header pstate =
  let ctype = content_type_of_int pstate (pop_byte pstate) in
  let maj = pop_byte pstate in
  let min = pop_byte pstate in
  let len = extract_uint16 pstate in
  (ctype, {major = maj; minor = min}, len)


let string_of_record_content = function
  | ChangeCipherSpec -> "ChangeCipherSpec"
  | Alert (level, t) ->
    "Alert (" ^ (string_of_alert_level level) ^ "): " ^
      (string_of_alert_type t)
  | Handshake hmsg ->
    "Handshake: " ^ (string_of_handshake_msg hmsg)
  | ApplicationData s ->
    "Application Data: " ^ (Common.hexdump s)
  | UnparsedRecord (ct, s) ->
    (string_of_content_type ct) ^ " (len=" ^
      (string_of_int (String.length s)) ^ "): " ^
      (Common.hexdump s)

let type_of_record_content = function
  | ChangeCipherSpec -> CT_ChangeCipherSpec
  | Alert _ -> CT_Alert
  | Handshake _ -> CT_Handshake
  | ApplicationData _ -> CT_ApplicationData
  | UnparsedRecord (ct, _) -> ct


let string_of_record r =
  "TLS Record (" ^ (string_of_protocol_version r.version) ^
    "): " ^ (string_of_record_content r.content)

let parse_record asn1_ehf pstate =
  let (ctype, version, len) = extract_record_header pstate in
  go_down pstate (string_of_content_type ctype) len;
  let content = match ctype with
    | CT_ChangeCipherSpec -> parse_change_cipher_spec pstate
    | CT_Alert -> parse_alert pstate
    | CT_Handshake -> parse_handshake asn1_ehf pstate
    | CT_ApplicationData
    | CT_Unknown _ -> UnparsedRecord (ctype, pop_string pstate)
  in
  go_up pstate;
  { version = version; content = content}


let pstate_of_channel = Engine.pstate_of_channel
let pstate_of_string = Engine.pstate_of_string
