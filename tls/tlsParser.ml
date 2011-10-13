open Tls

module TlsEngineParams = struct
  type parsing_error =
    | InternalMayhem
    | OutOfBounds of string
    | UnexpectedContentType of int
    | UnexpectedChangeCipherSpecValue of int
    | UnexpectedAlertLevel of int
    | UnexpectedAlertType of int
    | NotImplemented of string

  let out_of_bounds_error s = OutOfBounds s

  let string_of_perror = function
    | InternalMayhem -> "Internal mayhem"
    | OutOfBounds s -> "Out of bounds (" ^ s ^ ")"
    | UnexpectedJunk -> "Unexpected junk"
    | UnknownContentType x -> "Unknown content type " ^ (string_of_int x)
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
open Tls;;
open Engine;;


(* Trivial parsing functions *)

let extract_uint24 pstate =
  let res = pop_bytes pstate 3 in
  (res.(0) lsl 16) lor (res.(1) lsl 8) lor res.(2)

let extract_uint16 pstate =
  let res = pop_bytes pstate 2 in
  (res.(0) lsl 8) lor res.(1)


(* Record header *)

let content_type_of_int pstate = function
  | 20 -> CT_ChangeCipherSpec
  | 21 -> CT_Alert
  | 22 -> CT_Handshake
  | 23 -> CT_ApplicationData
  | x -> CT_Unknown
    emit (UnexpectedContentType x) S_Benign pstate;
    CT_Unknown x

let extract_header pstate =
  let ctype = content_type_of_int pstate (pop_byte pstate) in
  let maj = pop_byte pstate in
  let min pop_byte pstate in
  let len = extract_uint16 pstate in
  { ctype = ctype; version = {major = maj; minor = min}; length = len}


(* ChangeCipherSpec *)

let parse_change_cipher_spec pstate =
  let v = pop_byte pstate in
  if v <> 1 then emit (UnexpectedChangeCipherSpecValue v);
  if not (eos pstate) then emit UnexpectedJunk
  ChangeCipherSpec


(* Alert *)

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
    emit (UnexpectedAlertType x) S_Benign 
    UnknownAlertType x

let parse_alert pstate =
  let level = pop_byte pstate in
  let t = pop_byte pstate in
  if not (eos pstate) then emit UnexpectedJunk;
  Alert (alert_level_of_int level) (alert_type_of_int t)
