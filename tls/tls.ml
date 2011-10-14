open X509Directory

(* Alert *)

type alert_level =
  | AL_Warning
  | AL_Fatal
  | AL_Unknown of int

let string_of_alert_level = function
  | AL_Warning -> "Warning"
  | AL_Fatal -> "Fatal"
  | AL_Unknown x -> "Unknown alert level " ^ (string_of_int x)

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



(* Handshake *)

type protocol_version = { major : int; minor : int }

let string_of_protocol_version v = match (v.major, v.minor) with
  | 2, 0 -> "SSLv2"
  | 3, 0 -> "SSLv3"
  | 3, 1 -> "TLSv1.0"
  | 3, 2 -> "TLSv1.1"
  | 3, 3 -> "TLSv1.2"
  | maj, min -> "version" ^ (string_of_int maj) ^ "." ^ (string_of_int min)


type cipher_suite = int


type compression_method =
  | CM_Null
  | CM_Unknown of int

let string_of_compression_method = function
  | CM_Null -> "Null"
  | CM_Unknown x -> Common.hexdump_int 2 x


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

let string_of_client_hello ch =
  "Client Hello:" ^
    "\n  protocol version: " ^ (string_of_protocol_version ch.c_version) ^
    "\n  random: " ^ (Common.hexdump ch.c_random) ^
    "\n  session id: " ^ (Common.hexdump ch.c_session_id) ^
    "\n  cipher suites: " ^ (String.concat ", " (List.map (Common.hexdump_int 4) ch.c_cipher_suites)) ^
    "\n  compression methods: " ^ (String.concat ", " (List.map string_of_compression_method ch.c_compression_methods)) ^
    (* Extensions ... *)
    "\n"

type server_hello = {
  s_version : protocol_version;
  s_random : random;
  s_session_id : session_id;
  s_cipher_suite : cipher_suite;
  s_compression_method : compression_method;
  s_extensions : (tls_extension list) option
}

let string_of_server_hello sh =
  "Server Hello:" ^
    "\n  protocol version: " ^ (string_of_protocol_version sh.s_version) ^
    "\n  random: " ^ (Common.hexdump sh.s_random) ^
    "\n  session id: " ^ (Common.hexdump sh.s_session_id) ^
    "\n  cipher suite: " ^ (Common.hexdump_int 4 sh.s_cipher_suite) ^
    "\n  compression method: " ^ (string_of_compression_method sh.s_compression_method) ^
    (* Extensions ... *)
    "\n"


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



(* Record *)

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


type record_content =
  | ChangeCipherSpec
  | Alert of alert_level * alert_type
  | Handshake of handshake_msg
  | ApplicationData of string
  | UnparsedRecord of content_type * string

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

type record = {
  version : protocol_version;
  content : record_content
}

let string_of_record r =
  "TLS Record (" ^ (string_of_protocol_version r.version) ^
    "): " ^ (string_of_record_content r.content)
