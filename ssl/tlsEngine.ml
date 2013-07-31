open Lwt
open TlsEnums
open TlsDatabase
open Tls
open Parsifal


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
		  (string_of_tls_version min) (string_of_tls_version max)))

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
  ()
(*  match sh.server_extensions with
  | None | Some [] -> ()
  | _ -> failwith "Extensions not supported for now" *)

let update_with_server_hello ctx sh =
  (* TODO: exts *)
  ctx.future.s_server_random <- sh.server_random;
  ctx.future.s_session_id <- sh.server_session_id;
  ctx.future.s_version <- sh.server_version;
  ctx.future.s_ciphersuite <- find_csdescr sh.ciphersuite;
  ctx.future.s_compression_method <- sh.compression_method;
  ()
(*  match sh.server_extensions with
  | None | Some [] -> ()
  | _ -> failwith "Extensions not supported for now" *)


let update_with_certificate ctx cert =
  ctx.future.s_certificates <- cert


let update_with_server_key_exchange ctx ske =
  ctx.future.s_server_key_exchange <- ske





(* Useful functions *)

let write_record o record =
  let s = exact_dump_tls_record record in
  LwtUtil.really_write o s

let split_record record size =
  let ct = record.content_type
  and v = record.record_version
  and content = exact_dump_record_content record.record_content in
  let len = String.length content in
  let rec mk_records accu offset =
    if offset >= len
    then List.rev accu
    else begin
      let next_offset =
	if offset + size >= len
	then len
	else offset + size
      in
      let next = { content_type = ct;
		   record_version = v;
		   record_content = Unparsed_Record (String.sub content offset (next_offset - offset)) } in
      mk_records (next::accu) next_offset
    end
  in
  mk_records [] 0

let send_plain_record out record =
  let recs = split_record record !plaintext_chunk_size in
  Lwt_list.iter_s (write_record out) recs

(* TODO: compress/mac/encrypt the records *)
let send_record _ctx _out _record =
  fail (ParsingException (NotImplemented "send_record", []))








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
  | Retry

let catch_exceptions retry e =
  if retry > 1
  then return Retry
  else match e with
  | LwtUtil.Timeout -> return Timeout
  | End_of_file -> return EndOfFile
  | e -> fail e

let handle_answer handle_hs handle_alert s =
  let ctx = empty_context () in

  let process_input parse_fun handle_fun input =
    match try_parse parse_fun input with
      | None -> NothingSoFar, input
      | Some parsed_msg ->
	let res = handle_fun parsed_msg in
	let new_input = drop_used_string input in
	res, new_input
  in

  let rec read_answers hs_in alert_in =
    lwt_parse_tls_record None s >>= fun record ->
    let result, new_hs_in, new_alert_in = match record.content_type with
      | CT_Handshake ->
	let input = append_to_input hs_in (exact_dump_record_content record.record_content) in
	let r, h = process_input (parse_handshake_msg (Some ctx)) (handle_hs ctx) input in
	r, h, alert_in
      | CT_Alert ->
	let input = append_to_input alert_in (exact_dump_record_content record.record_content) in
	let r, a = process_input parse_tls_alert handle_alert input in
	r, hs_in, a
      | _ -> FatalAlert "Unexpected content type", hs_in, alert_in
    in match result with
      | NothingSoFar -> timed_read_answers new_hs_in new_alert_in
      | x -> return x
  and timed_read_answers hs_in alert_in =
    let t = read_answers hs_in alert_in in
    pick [t; Lwt_unix.sleep !timeout >>= fun () -> return Timeout]
  in

  let hs_in = input_of_string "Handshake records" ""
  and alert_in = input_of_string "Alert records" "" in
  catch (fun () -> timed_read_answers hs_in alert_in) (catch_exceptions 0)


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



let _ =
  enrich_suite_hash ()
