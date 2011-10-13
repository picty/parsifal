(* Types *)

type protocol_version = { major : int; minor : int }

let string_of_protocol_version v = match (v.major, v.minor) with
  | 2, 0 -> "SSLv2"
  | 3, 0 -> "SSLv3"
  | 3, 1 -> "TLSv1.0"
  | 3, 2 -> "TLSv1.1"
  | 3, 3 -> "TLSv1.2"
  | maj, min -> "version" ^ (string_of_int maj) ^ "." ^ (string_of_int min)

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

type record_header = {
  ctype : content_type;
  version : protocol_version;
  length : int
}

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


type record_content =
  | ChangeCipherSpec
  | Alert of alert_level * alert_type

let string_of_record_content = function
  | ChangeCipherSpec -> "ChangeCipherSpec"
  | Alert (level, t) ->
    "Alert (" ^ (string_of_alert_level level) ^ "): " ^
      (string_of_alert_type t)


type record = {
  version : protocol_version;
  content : record_content
}

let string_of_record r =
  "TLS Record (" ^ (string_of_protocol_version r.version) ^
    "): " ^ (string_of_record_content r.content)
