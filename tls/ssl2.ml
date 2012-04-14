open Common
open Types
open Printer
open Modules
open ParsingEngine
open BinaryRecord
open TlsCommon


type ssl2_errors =
  | UnexpectedMsgType
  | UnexpectedJunk

let ssl2_errors_strings = [|
  (UnexpectedMsgType, s_benign, "Unexpected handshake message type");
  (UnexpectedJunk, s_idempotencebreaker, "Unexpected junk in handshake message");
|]

let ssl2_emit = register_module_errors_and_make_emit_function "ssl2" ssl2_errors_strings


let parse_certificates = ref false (* TODO: Is this the good default? *)



(* Handshake message type *)

type msg_type = int

let message_type_string_of_int = function
  | 0 -> "Error"
  | 1 -> "Client Hello"
  | 2 -> "Client Master Key"
  | 3 -> "Client Finished"
  | 4 -> "Server Hello"
  | 5 -> "Server Verify"
  | 6 -> "Server Finished"
  | 7 -> "Request Certificate"
  | 8 -> "Client Certificate"
  | x -> "Unknown message type " ^ (string_of_int x)

let message_type_int_of_string = function
  | "Error" -> 0
  | "Client Hello" -> 1
  | "Client Master Key" -> 2
  | "Client Finished" -> 3
  | "Server Hello" -> 4
  | "Server Verify" -> 5
  | "Server Finished" -> 6
  | "Request Certificate" -> 7
  | "Client Certificate" -> 8
  | s -> int_of_string s

let check_message_type pstate = function
  | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 -> ()
  | x -> ssl2_emit UnexpectedMsgType None (Some (string_of_int x)) pstate

let pop_message_type pstate =
  let hmt = pop_byte pstate in
  check_message_type pstate hmt;
  hmt

let _make_message_type = function
  | V_Int i
  | V_Enumerated (i, _) -> i
  | V_String s -> message_type_int_of_string s
  | _ -> raise (ContentError "Invalid handshake message type value")

let make_message_type v = V_Enumerated (_make_message_type v, message_type_string_of_int)



let assert_eos pstate =
  if not (eos pstate)
  then ssl2_emit UnexpectedJunk None (Some (hexdump (pop_string pstate))) pstate


let extract_header pstate =
  let b0 = pop_byte pstate in
  let b1 = pop_byte pstate in
  let record_len, pad_len =
    if b0 land 0x80 <> 0
    then ((b0 land 0x7f) lsl 8) lor b1, 0
    else ((b0 land 0x3f) lsl 8) lor b1, pop_byte pstate
  in
  let t = pop_message_type pstate in
  (t, record_len - pad_len - 1, pad_len)


type ssl2Msg =
  | ClientHello of (protocol_version * int list * string * string)
  | UnknownMsg of string

let parse_client_hello pstate =
  let version = pop_uint16 pstate in
  let cs_len = pop_uint16 pstate in
  let sid_len = pop_uint16 pstate in
  let challenge_len = pop_uint16 pstate in
  let ciphersuites = pop_fixedlen_list "Cipher suites" cs_len pop_uint24 pstate in
  let sid = pop_fixedlen_string sid_len pstate in
  let challenge = pop_fixedlen_string challenge_len pstate in
  ClientHello (version, ciphersuites, sid, challenge) 


let parse pstate =
  let (t, real_len, pad_len) = extract_header pstate in
  let new_pstate = go_down pstate (message_type_string_of_int t) real_len in
  let res = match t with
    | 1 -> parse_client_hello new_pstate
    (*    | 2 -> parse_server_hello pstate
	  | 11 -> parse_certificate_msg pstate
	  | 0 | 14 -> V_Unit*)
    | _ -> UnknownMsg (pop_string new_pstate)
  in
  assert_eos new_pstate;
  drop_bytes pstate pad_len;
  res
