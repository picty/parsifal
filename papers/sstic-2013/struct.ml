enum tls_alert_level (8, UnknownVal AL_Unknown) =
  | 1 -> AL_Warning, "Warning"
  | 2 -> AL_Fatal, "Fatal"

enum tls_alert_type (8, UnknownVal AT_Unknown) =
  | 0 -> AT_CloseNotify, "CloseNotify"
  | 10 -> AT_UnexpectedMessage, "UnexpectedMessage"
  | 110 -> AT_UnsupportedExtension, "UnsupportedExtension"

struct tls_alert = {
  alert_level : tls_alert_level;
  alert_type : tls_alert_type
}
