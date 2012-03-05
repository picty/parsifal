(* cf RFC 6520 *)

open Common
open Types
open Modules
open ParsingEngine
open TlsCommon


type tls_heartbeat_errors =
  | UnexpectedHeartbeatType
  | UnexpectedHeartbeatMode

let tls_heartbeat_errors_strings = [|
  (UnexpectedHeartbeatType, s_benign, "Unexpected heartbeat type");
  (UnexpectedHeartbeatMode, s_benign, "Unexpected heartbeat mode");
|]

let tls_heartbeat_emit = register_module_errors_and_make_emit_function "tlsHeartbeat" tls_heartbeat_errors_strings


(* Heartbeat Type *)

type heartbeat_type = int

let heartbeat_type_string_of_int = function
  | 1 -> "Request"
  | 2 -> "Response"
  | x -> "Unknown heartbeat type " ^ (string_of_int x)

let heartbeat_type_int_of_string = function
  | "Request" | "request" -> 1
  | "Response" | "response" -> 2
  | s -> int_of_string s

let check_heartbeat_type pstate = function
  | 1 | 2 -> ()
  | x -> tls_heartbeat_emit UnexpectedHeartbeatType None (Some (string_of_int x)) pstate

let pop_heartbeat_type pstate =
  let ht = pop_byte pstate in
  check_heartbeat_type pstate ht;
  ht

let _make_heartbeat_type = function
  | V_Int i
  | V_Enumerated (i, _) -> i
  | V_String s -> heartbeat_type_int_of_string s
  | _ -> raise (ContentError "Invalid heartbeat type value")

let make_heartbeat_type v = V_Enumerated (_make_heartbeat_type v, heartbeat_type_string_of_int)


(* Heartbeat Mode *)

(* mode heartbeat_mode = int

let heartbeat_mode_string_of_int = function
  | 1  -> "peer_allowed_to_send"
  | 2  -> "peer_not_allowed_to_send"
  | x  -> "Unknown heartbeat mode " ^ (string_of_int x)

let heartbeat_mode_int_of_string = function
  | "peer_allowed_to_send" -> 1
  | "peer_not_allowed_to_send" -> 2
  | s -> int_of_string s

let check_heartbeat_mode pstate = function
  | 1 | 2  -> ()
  | x -> tls_heartbeat_emit UnexpectedHeartbeatMode None (Some (string_of_int x)) pstate

let pop_heartbeat_mode pstate =
  let hm = pop_byte pstate in
  check_heartbeat_mode pstate hm;
  hm

let _make_heartbeat_mode = function
  | V_Int i
  | V_Enumerated (i, _) -> i
  | V_String s -> heartbeat_mode_int_of_string s
  | _ -> raise (ContentError "Invalid heartbeat type value")

let make_heartbeat_mode v = V_Enumerated (_make_heartbeat_mode v, heartbeat_mode_string_of_int) *)


(* HeartbeatParser *)

module HeartbeatParser = struct
  let name = "heartbeat"
  (* TODO: Use BinaryRecord? *)
  type t = heartbeat_type * string * string

  let parse pstate =
    let ht = pop_heartbeat_type pstate in
    let payload = pop_varlen_string pop_uint16 pstate in
    let padding = pop_string pstate in
    (ht, payload, padding)

  let dump (heartbeat_type, payload, padding) =
    (dump_uint8 heartbeat_type) ^ (dump_uint16 (String.length payload)) ^ payload ^ padding

  let enrich (heartbeat_type, payload, padding) dict =
    Hashtbl.replace dict "type" (V_Enumerated (heartbeat_type, heartbeat_type_string_of_int));
    Hashtbl.replace dict "payload" (V_BinaryString payload);
    Hashtbl.replace dict "padding" (V_BinaryString padding);
    ()

  let update dict =
    let ht = _make_heartbeat_type (hash_find dict "type")
    and payload = eval_as_string (hash_find dict "payload")
    and padding = eval_as_string (hash_find dict "padding") in
    (ht, payload, padding)

  let to_string (heartbeat_type, _, _) =
    ["TLS Heartbeat (" ^ (heartbeat_type_string_of_int heartbeat_type) ^ ")"]

  let params = []
  let functions = [
(* TODO !!!! *)
(*    ("mk_type", fun _ -> one_value_fun make_heartbeat_type); *)
  ]
end

module HeartbeatModule = MakeParserModule (HeartbeatParser)

let _ = add_object_module ((module HeartbeatModule : ObjectModule))
