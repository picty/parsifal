open Tls

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

let extract_uint24 pstate =
  let res = pop_bytes pstate 3 in
  (res.(0) lsl 16) lor (res.(1) lsl 8) lor res.(2)

let extract_uint16 pstate =
  let res = pop_bytes pstate 2 in
  (res.(0) lsl 8) lor res.(1)

let extract_string name len pstate =
  go_down pstate name len;
  let res = pop_string pstate in
  go_up pstate;
  res

let extract_variable_length_string name length_fun pstate =
  let len = length_fun pstate in
  go_down pstate name len;
  let res = pop_string pstate in
  go_up pstate;
  res

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

let compression_method_of_int = function
  | 0 -> CM_Null
  | x -> CM_Unknown x

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

let parse_handshake pstate =
  let (htype, len) = extract_handshake_header pstate in
  go_down pstate (string_of_handshake_msg_type htype) len;
  let content = match htype with
    | H_HelloRequest ->
      assert_eos pstate;
      HelloRequest
    | H_ClientHello -> parse_client_hello pstate
    | H_ServerHello -> parse_server_hello pstate
    | H_Certificate
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


let parse_record pstate =
  let (ctype, version, len) = extract_record_header pstate in
  go_down pstate (string_of_content_type ctype) len;
  let content = match ctype with
    | CT_ChangeCipherSpec -> parse_change_cipher_spec pstate
    | CT_Alert -> parse_alert pstate
    | CT_Handshake -> parse_handshake pstate
    | CT_ApplicationData
    | CT_Unknown _ -> UnparsedRecord (ctype, pop_string pstate)
  in
  go_up pstate;
  { version = version; content = content}
