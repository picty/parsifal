open Types
open Modules
open ParsingEngine
open TlsCommon


type tls_alert_errors =
  | UnexpectedAlertLevel
  | UnexpectedAlertType
  | UnexpectedJunk

let tls_alert_errors_strings = [|
  (UnexpectedAlertLevel, s_benign, "Unexpected alert level");
  (UnexpectedAlertType, s_benign, "Unexpected alert type");
  (UnexpectedJunk, s_idempotencebreaker, "Unexpected junk at the end of an alert");
|]

let tls_alert_emit = register_module_errors_and_make_emit_function "tlsAlert" tls_alert_errors_strings



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
    tls_alert_emit UnexpectedAlertLevel None (Some (string_of_int x)) pstate;
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
    tls_alert_emit UnexpectedAlertType None (Some (string_of_int x)) pstate;
    UnknownAlertType x

module AlertParser = struct
  let name = "alert"
  type t = alert_level * alert_type

  let parse pstate =
    let level = pop_byte pstate in
    let t = pop_byte pstate in
    if not (eos pstate)
    then tls_alert_emit UnexpectedJunk None (Some (Common.hexdump (pop_string pstate))) pstate;
    (alert_level_of_int pstate level, alert_type_of_int pstate t)

  let dump alert = raise NotImplemented

  let enrich (alert_level, alert_type) dict =
    Hashtbl.replace dict "level" (V_String (string_of_alert_level (alert_level)));
    Hashtbl.replace dict "type" (V_String (string_of_alert_type (alert_type)));
    ()

  let update dict = raise NotImplemented

  let to_string _ (alert_level, alert_type) =
    "TLS Alert (" ^ (string_of_alert_level alert_level) ^ "): " ^ (string_of_alert_type alert_type)

  let params = []
end

module AlertModule = MakeParserModule (AlertParser)

let _ =
  add_module ((module AlertModule : Module));
  ()
