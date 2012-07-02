open Lwt
open TlsEnums
open Tls

type 'a tls_function = TlsContext.tls_context -> tls_record Lwt_mvar.t -> 'a Lwt.t

exception TLS_AlertToSend of alert_type * string

type 'a tls_state =
  | FatalAlertReceived of tls_alert_type
  | FatalAlertToSend of tls_alert_type * string
  | FirstPhaseOK of tls_alert_type list * tls_alert_type list        (* warning alerts received and to send *)
  | NegotiationComplete of tls_alert_type list * tls_alert_type list (* warning alerts received and to send *)


(* CLIENT AUTOMATA *)

let update_with_client_hello ctx ch = ()

let update_with_server_hello ctx sh =
  (* TODO: check/add the version, the random, the session_id, the compression, the exts *)
  (*  ctx.future.server_version <- sh.server_version *)
  ctx.TlsContext.future.TlsContext.ciphersuite <- sh.ciphersuite

let update_with_certificate _ctx _cert = ()

let update_with_ske _ctx _cert = ()



(* TODO: factor the code to handle simply alerts and  *)

let wrap_expect_fun f ctx recs =
  Lwt_mvar.take recs >>= fun record ->
  try
    begin
      match record.record_content with
      | Alert { alert_level = AL_Warning } ->
	expect_server_hello ctx recs
      | Alert { alert_level = AL_Fatal; alert_type = t } ->
	return (FatalAlertReceived (t, ""))
      | _ -> f record
    end
  with
  | FatalAlertToSend (at, s) -> return (FatalAlertToSend (at, s))
  | e -> return (FatalAlertToSend (AT_InternalError, (Printexc.to_string e)))


let rec _expect_server_hello = function
  | Handshake {handshake_content = ServerHello sh} ->
    update_with_serverhello ctx sh;
    (* Expect certif, SKE or SHD *)
    expect_certificate ctx recs
  | _ -> raise (TLS_AlertToSend (AT_UnexpectedMessage, "ServerHello expected"))
and expect_server_hello = wrap_expect_fun _expect_server_hello

and _expect_certificate = function
  | Handshake {handshake_content = Certificate cert} ->
      update_with_certificate ctx cert;
      (* Expect SKE or SHD *)
      expect_ske ctx recs
  | _ -> raise (TLS_AlertToSend (AT_UnexpectedMessage, "Certificate expected"))
and expect_certificate = wrap_expect_fun _expect_certificate

and _expect_server_key_exchange = function
  | Handshake {handshake_content = ServerKeyExchange ske} ->
    update_with_ske ctx ske;
    (* CertificateRequest ? *)
    expect_shd ctx recs
  | _ -> raise (TLS_AlertToSend (AT_UnexpectedMessage, "ServerKeyExchange expected"))
and expect_server_key_exchange = wrap_expect_fun _expect_server_key_exchange

and _expect_server_hello_done = function
  | Handshake {handshake_content = ServerHelloDone ()} -> return (FirstPhaseOK ([], []))
  | _ -> raise (TLS_AlertToSend (AT_UnexpectedMessage, "ServerHelloDone expected"))
and expect_server_hello_done = wrap_expect_fun _expect_server_hello_done
 
