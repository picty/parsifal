open Lwt
open TlsEnums
open TlsDatabase
open Tls
open ParsingEngine


exception TLS_AlertToSend of tls_alert_type * string


(* GLOBAL PARAMS *)

let plaintext_chunk_size = ref 16384
let timeout = ref 3.0



(* AUTOMATA *)

let update_with_client_hello ctx ch =
  (* TODO: extensions *)
  ctx.future.versions_proposed <- (V_SSLv3, ch.client_version);
  ctx.future.s_client_random <- ch.client_random;
  ctx.future.s_session_id <- ch.client_session_id;
  ctx.future.ciphersuites_proposed <- ch.ciphersuites;
  ctx.future.compressions_proposed <- ch.compression_methods;
  match ch.client_extensions with
  | None | Some [] -> ()
  | _ -> failwith "Extensions not supported for now"


let check_server_version ctx v =
  let min, max = ctx.future.versions_proposed in
  if not ((int_of_tls_version min < int_of_tls_version v) &&
	     (int_of_tls_version v < int_of_tls_version max))
  then raise (TLS_AlertToSend (AT_ProtocolVersion,
	        Printf.sprintf "A version between %s and %s was expected"
		  (print_tls_version min) (print_tls_version max)))

let check_ciphersuite ctx cs =
  if  not (List.mem cs ctx.future.ciphersuites_proposed)
  then raise (TLS_AlertToSend (AT_HandshakeFailure, "Unexpected ciphersuite"))

let check_compression ctx cm =
  if not (List.mem cm ctx.future.compressions_proposed)
  then raise (TLS_AlertToSend (AT_HandshakeFailure, "Unexpected compression method"))

let check_server_hello ctx sh =
  (* TODO: exts *)
  check_server_version ctx sh.server_version;
  check_ciphersuite ctx sh.ciphersuite;
  check_compression ctx sh.compression_method;
  match sh.server_extensions with
  | None | Some [] -> ()
  | _ -> failwith "Extensions not supported for now"

let update_with_server_hello ctx sh =
  (* TODO: exts *)
  ctx.future.s_server_random <- sh.server_random;
  ctx.future.s_session_id <- sh.server_session_id;
  ctx.future.s_version <- sh.server_version;
  ctx.future.s_ciphersuite <- find_csdescr sh.ciphersuite;
  ctx.future.s_compression_method <- sh.compression_method;
  match sh.server_extensions with
  | None | Some [] -> ()
  | _ -> failwith "Extensions not supported for now"


let update_with_certificate _ctx _cert = ()


let update_with_server_key_exchange ctx ske =
  ctx.future.s_server_key_exchange <- ske


(* Useful functions *)

let write_record o record =
  let s = dump_tls_record record in
  LwtUtil.really_write o s

let send_plain_record out record =
  let recs = TlsUtil.split_record record !plaintext_chunk_size in
  Lwt_list.iter_s (write_record out) recs

(* TODO: compress/mac/encrypt the records *)
let send_record ctx out record =
  fail (Common.NotImplemented "send_record")








(* type 'a tls_function = tls_context -> tls_record Lwt_mvar.t -> 'a Lwt.t *)

(* type 'a tls_state = *)
(*   | FatalAlertReceived of tls_alert_type *)
(*   | FatalAlertToSend of tls_alert_type * string *)
(*   | FirstPhaseOK of tls_alert_type list * tls_alert_type list        (\* warning alerts received and to send *\) *)
(*   | NegotiationComplete of tls_alert_type list * tls_alert_type list (\* warning alerts received and to send *\) *)



(* TODO: handle_answer is probe-server oriented *)
type 'a result_type =
  | NothingSoFar
  | Result of 'a
  | FatalAlert of string
  | EndOfFile
  | Timeout

let catch_exceptions = function
  | Util.Timeout -> return Timeout
  | End_of_file -> return EndOfFile
  | e -> fail e

let handle_answer handle_hs handle_alert s =
  let ctx = empty_context () in
  let hs_in = input_of_string "Handshake records" ""
  and alert_in = input_of_string "Alert records" "" in

  let process_input parse_fun handle_fun input =
    match try_parse parse_fun input with
      | None -> NothingSoFar
      | Some parsed_msg ->
	let res = handle_fun parsed_msg in
	drop_used_string input;
	res
  in

  let rec read_answers () =
    lwt_parse_tls_record None s >>= fun record ->
    let result = match record.content_type with
      | CT_Handshake ->
	append_to_input hs_in (dump_record_content record.record_content);
	process_input (parse_handshake_msg (Some ctx)) (handle_hs ctx) hs_in
      | CT_Alert ->
	append_to_input alert_in (dump_record_content record.record_content);
	process_input parse_tls_alert handle_alert alert_in
      | _ -> FatalAlert "Unexpected content type"
    in match result with
      | NothingSoFar -> timed_read_answers ()
      | x -> return x
  and timed_read_answers () =
    let t = read_answers () in
    pick [t; Lwt_unix.sleep !timeout >>= fun () -> return Timeout]
  in

  catch timed_read_answers catch_exceptions


(* let rec wrap_expect_fun f ctx recs = *)
(*   Lwt_mvar.take recs >>= fun record -> *)
(*   try *)
(*     begin *)
(*       match record.record_content with *)
(*       | Alert { alert_level = AL_Warning } -> *)
(* 	wrap_expect_fun f ctx recs *)
(*       | Alert { alert_level = AL_Fatal; alert_type = t } -> *)
(* 	return (FatalAlertReceived t) *)
(*       | rc -> f ctx recs rc *)
(*     end *)
(*   with *)
(*   | TLS_AlertToSend (at, s) -> return (FatalAlertToSend (at, s)) *)
(*   | e -> return (FatalAlertToSend (AT_InternalError, (Printexc.to_string e))) *)


(* let rec _expect_server_hello ctx recs = function *)
(*   | Handshake {handshake_content = ServerHello sh} -> *)
(*     update_with_server_hello ctx sh; *)
(*     (\* Expect certif, SKE or SHD *\) *)
(*     expect_certificate ctx recs *)
(*   | _ -> raise (TLS_AlertToSend (AT_UnexpectedMessage, "ServerHello expected")) *)
(* and expect_server_hello ctx recs = wrap_expect_fun _expect_server_hello ctx recs *)

(* and _expect_certificate ctx recs = function *)
(*   | Handshake {handshake_content = Certificate cert} -> *)
(*       update_with_certificate ctx cert; *)
(*       (\* Expect SKE or SHD *\) *)
(*       expect_server_key_exchange ctx recs *)
(*   | _ -> raise (TLS_AlertToSend (AT_UnexpectedMessage, "Certificate expected")) *)
(* and expect_certificate ctx recs = wrap_expect_fun _expect_certificate ctx recs *)

(* and _expect_server_key_exchange ctx recs = function *)
(*   | Handshake {handshake_content = ServerKeyExchange ske} -> *)
(*     update_with_ske ctx ske; *)
(*     (\* CertificateRequest ? *\) *)
(*     expect_server_hello_done ctx recs *)
(*   | _ -> raise (TLS_AlertToSend (AT_UnexpectedMessage, "ServerKeyExchange expected")) *)
(* and expect_server_key_exchange ctx recs = wrap_expect_fun _expect_server_key_exchange ctx recs *)

(* and _expect_server_hello_done ctx recs = function *)
(*   | Handshake {handshake_content = ServerHelloDone ()} -> return (FirstPhaseOK ([], [])) *)
(*   | _ -> raise (TLS_AlertToSend (AT_UnexpectedMessage, "ServerHelloDone expected")) *)
(* and expect_server_hello_done ctx recs = wrap_expect_fun _expect_server_hello_done ctx recs *)
