enum tls_alert_level (8, UnknownVal AL_Unknown) =
  | 1 -> AL_Warning, "Warning"
  | 2 -> AL_Fatal, "Fatal"


enum tls_alert_type (8, UnknownVal AT_Unknown) =
  | 0 -> AT_CloseNotify, "CloseNotify"
  | 10 -> AT_UnexpectedMessage, "UnexpectedMessage"
  | 20 -> AT_BadRecordMAC, "BadRecordMAC"
  | 21 -> AT_DecryptionFailed, "DecryptionFailed"   (* Reserved *)
  | 22 -> AT_RecordOverflow, "RecordOverflow"
  | 30 -> AT_DecompressionFailure, "DecompressionFailure"
  | 40 -> AT_HandshakeFailure, "HandshakeFailure"
  | 41 -> AT_NoCertificate, "NoCertificate"         (* Reserved *)
  | 42 -> AT_BadCertificate, "BadCertificate"
  | 43 -> AT_UnsupportedCertificate, "UnsupportedCertificate"
  | 44 -> AT_CertificateRevoked, "CertificateRevoked"
  | 45 -> AT_CertificateExpired, "CertificateExpired"
  | 46 -> AT_CertificateUnknown, "CertificateUnknown"
  | 47 -> AT_IllegalParameter, "IllegalParameter"
  | 48 -> AT_UnknownCA, "UnknownCA"
  | 49 -> AT_AccessDenied, "AccessDenied"
  | 50 -> AT_DecodeError, "DecodeError"
  | 51 -> AT_DecryptError, "DecryptError"
  | 60 -> AT_ExportRestriction, "ExportRestriction" (* Reserved *)
  | 70 -> AT_ProtocolVersion, "ProtocolVersion"
  | 71 -> AT_InsufficientSecurity, "InsufficientSecurity"
  | 80 -> AT_InternalError, "InternalError"
  | 90 -> AT_UserCanceled, "UserCanceled"
  | 100 -> AT_NoRenegotiation, "NoRenegotiation"
  | 110 -> AT_UnsupportedExtension, "UnsupportedExtension"
  | 111 -> AT_CertificateUnobtainable, "CerttificateUnobtainable"
  | 112 -> AT_UnrecognizedName, "UnrecognizedName"
  | 113 -> AT_BadCertificateStatusResponse, "BadCertificateStatusResponse"
  | 114 -> AT_BadCertificateHashValue, "BadCertificateHashValue"
  | 115 -> AT_UnknownPSKIdentity, "UnknownPSKIdentity"

struct tls_alert =
{
  alert_level : tls_alert_level;
  alert_type : tls_alert_type
}
