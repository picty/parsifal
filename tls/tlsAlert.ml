open Common
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


(* Alert Level *)

type alert_level = int

let alert_level_string_of_int = function
  | 1 -> "Warning"
  | 2 -> "Fatal"
  | x -> "Unknown alert level " ^ (string_of_int x)

let alert_level_int_of_string = function
  | "Warning" | "warning" -> 1
  | "Fatal" | "fatal" -> 2
  | s -> int_of_string s

let check_alert_level pstate = function
  | 1 | 2 -> ()
  | x -> tls_alert_emit UnexpectedAlertLevel None (Some (string_of_int x)) pstate

let pop_alert_level pstate =
  let al = pop_byte pstate in
  check_alert_level pstate al;
  al

let _make_alert_level = function
  | V_Int i
  | V_Enumerated (i, _) -> i
  | V_String s -> alert_level_int_of_string s
  | _ -> raise (ContentError "Invalid alert level value")

let make_alert_level v = V_Enumerated (_make_alert_level v, alert_level_string_of_int)


(* Alert Type *)

type alert_type = int

let alert_type_string_of_int = function
  | 0   -> "Close notify"
  | 10  -> "Unexpected message"
  | 20  -> "Bad record mac"
  | 21  -> "Decryption failed"
  | 22  -> "Record overflow"
  | 30  -> "Decompression failure"
  | 40  -> "Handshake failure"
  | 41  -> "No certificate"
  | 42  -> "Bad certificate"
  | 43  -> "Unsupported certificate"
  | 44  -> "Certificate revoked"
  | 45  -> "Certificate expired"
  | 46  -> "Certificate unknown"
  | 47  -> "Illegal parameter"
  | 48  -> "Unknown CA"
  | 49  -> "Access denied"
  | 50  -> "Decode error"
  | 51  -> "Decrypt error"
  | 60  -> "Export restriction"
  | 70  -> "Protocol version"
  | 71  -> "Insufficient security"
  | 80  -> "Internal error"
  | 90  -> "User canceled"
  | 100 -> "No renegotiation"
  | 110 -> "Unsupported extension"
  | x   -> "Unknown alert type " ^ (string_of_int x)

let alert_type_int_of_string = function
  | "Close notify" -> 0
  | "Unexpected message" -> 10
  | "Bad record mac" -> 20
  | "Decryption failed" -> 21
  | "Record overflow" -> 22
  | "Decompression failure" -> 30
  | "Handshake failure" -> 40
  | "No certificate" -> 41
  | "Bad certificate" -> 42
  | "Unsupported certificate" -> 43
  | "Certificate revoked" -> 44
  | "Certificate expired" -> 45
  | "Certificate unknown" -> 46
  | "Illegal parameter" -> 47
  | "Unknown CA" -> 48
  | "Access denied" -> 49
  | "Decode error" -> 50
  | "Decrypt error" -> 51
  | "Export restriction" -> 60
  | "Protocol version" -> 70
  | "Insufficient security" -> 71
  | "Internal error" -> 80
  | "User canceled" -> 90
  | "No renegotiation" -> 100
  | "Unsupported extension" -> 110
  | s -> int_of_string s

let check_alert_type pstate = function
  | 0 | 10 | 20 | 21 | 22 | 30 | 40 | 41 | 42
  | 43 | 44 | 45 | 46 | 47 | 48 | 49 | 50 | 51
  | 60 | 70 | 71 | 80 | 90 | 100 | 110  -> ()
  | x -> tls_alert_emit UnexpectedAlertType None (Some (string_of_int x)) pstate

let pop_alert_type pstate =
  let at = pop_byte pstate in
  check_alert_type pstate at;
  at

let _make_alert_type = function
  | V_Int i
  | V_Enumerated (i, _) -> i
  | V_String s -> alert_type_int_of_string s
  | _ -> raise (ContentError "Invalid alert level value")

let make_alert_type v = V_Enumerated (_make_alert_type v, alert_type_string_of_int)


(* AlertParser *)

module AlertParser = struct
  let name = "alert"
  type t = alert_level * alert_type

  let parse pstate =
    let al = pop_alert_level pstate in
    let at = pop_alert_type pstate in
    if not (eos pstate) then tls_alert_emit UnexpectedJunk None (Some (hexdump (pop_string pstate))) pstate;
    (al, at)

  let dump (alert_level, alert_type) = (dump_uint8 alert_level) ^ (dump_uint8 alert_type)

  let enrich (alert_level, alert_type) dict =
    Hashtbl.replace dict "level" (V_Enumerated (alert_level, alert_level_string_of_int));
    Hashtbl.replace dict "type" (V_Enumerated (alert_type, alert_type_string_of_int));
    ()

  let update dict =
    let al = _make_alert_level (hash_find dict "level")
    and at = _make_alert_type (hash_find dict "type") in
    (al, at)

  let to_string (alert_level, alert_type) =
    ["TLS Alert (" ^ (alert_level_string_of_int alert_level) ^ "): " ^ (alert_type_string_of_int alert_type)]

  let params = []
  let functions = [
    ("mk_level", fun _ -> one_value_fun make_alert_level);
    ("mk_type", fun _ -> one_value_fun make_alert_type)
  ]
end

module AlertModule = MakeParserModule (AlertParser)

let _ = add_object_module ((module AlertModule : ObjectModule))
