open Lwt
open TlsEnums
open Tls

type 'a tls_function = TlsContext.tls_context -> tls_record Lwt_mvar.t -> 'a Lwt.t

type 'a tls_state =
  | FatalAlertReceived of tls_alert_type * string
  | FatalAlertToSend of tls_alert_type * string
  | FirstPhaseOK of tls_alert_type list * tls_alert_type list        (* warning alerts received and to send *)
  | NegotiationComplete of tls_alert_type list * tls_alert_type list (* warning alerts received and to send *)


(* CLIENT AUTOMATA *)


(* TODO: the update function should return unit,
         but they should throw an exception of Alert * string when the client fails
         any other exception should result in an Internal error *)

let update_with_serverhello ctx sh =
  (* TODO: check/add the version, the random, the session_id, the compression, the exts *)
  (*  ctx.future.server_version <- sh.server_version *)
  ctx.TlsContext.future.TlsContext.ciphersuite <- sh.ciphersuite

let update_with_certificate _ctx _cert = ()

let update_with_ske _ctx _cert = ()



(* TODO: factor the code to handle simply alerts and  *)

let rec expect_server_hello ctx recs =
  Lwt_mvar.take recs >>= fun record ->
  match record.record_content with
    | Handshake {handshake_content = ServerHello sh} ->
      update_with_serverhello ctx sh;
      (* Expect certif, SKE or SHD *)
      expect_certificate ctx recs
    | Alert { alert_level = AL_Warning } ->
      expect_server_hello ctx recs
    | Alert { alert_level = AL_Fatal; alert_type = t } ->
      return (FatalAlertReceived (t, ""))
    | _ -> return (FatalAlertToSend (AT_UnexpectedMessage, "ServerHello expected"))

and expect_certificate ctx recs =
  Lwt_mvar.take recs >>= fun record ->
  match record.record_content with
    | Handshake {handshake_content = Certificate cert} ->
      update_with_certificate ctx cert;
      (* Expect SKE or SHD *)
      expect_ske ctx recs
    | Alert { alert_level = AL_Warning } ->
      expect_certificate ctx recs
    | Alert { alert_level = AL_Fatal; alert_type = t } ->
      return (FatalAlertReceived (t, ""))
    | _ -> return (FatalAlertToSend (AT_UnexpectedMessage, "Certificate expected"))
 
and expect_ske ctx recs =
  Lwt_mvar.take recs >>= fun record ->
  match record.record_content with
    | Handshake {handshake_content = ServerKeyExchange ske} ->
      update_with_ske ctx ske;
      (* CertificateRequest ? *)
      expect_shd ctx recs
    | Alert { alert_level = AL_Warning } ->
      expect_certificate ctx recs
    | Alert { alert_level = AL_Fatal; alert_type = t } ->
      return (FatalAlertReceived (t, ""))
    | _ -> return (FatalAlertToSend (AT_UnexpectedMessage, "ServerKeyExchange expected"))
 
and expect_shd ctx recs =
  Lwt_mvar.take recs >>= fun record ->
  match record.record_content with
    | Handshake {handshake_content = ServerHelloDone ()} -> return (FirstPhaseOK ([], []))
    | Alert { alert_level = AL_Warning } ->
      expect_shd ctx recs
    | Alert { alert_level = AL_Fatal; alert_type = t } ->
      return (FatalAlertReceived (t, ""))
    | _ -> return (FatalAlertToSend (AT_UnexpectedMessage, "ServerHelloDone expected"))
 
