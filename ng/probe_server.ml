(* see https://github.com/avsm/ocaml-cohttpserver/blob/master/server/http_tcp_server.ml *)

open Lwt
open Lwt_io
open Unix

open ParsingEngine
open DumpingEngine
open LwtParsingEngine
open Common
open TlsEnums
open Tls


let mk_client_hello v cs =
  let ch_hs_msg = {
    handshake_type = HT_ClientHello;
    handshake_content = ClientHello {
      client_version = v;
      client_random = String.make 32 '\x00';
      client_session_id = "";
      ciphersuites = cs;
      compression_methods = [CM_Null];
      client_extensions = None
    }
  } in {
    content_type = CT_Handshake;
    record_version = V_TLSv1;
    record_content = dump_handshake_msg ch_hs_msg
  }


let handle_answer handle_hs handle_alert s =
  let ctx = TlsContext.empty_context () in

  let hs_in, hs_out = Lwt_io.pipe ()
  and alert_in,alert_out = Lwt_io.pipe () in
  let hs_lwt_in = input_of_channel "Server handshake" hs_in
  and alert_lwt_in = input_of_channel "Server alerts" alert_in in

  let rec read_answers () =
    lwt_parse_tls_record s >>= fun record ->
    begin
      match record.content_type with
	| CT_Handshake ->
	  write_from_exactly hs_out record.record_content 0 (String.length record.record_content)
	| CT_Alert ->
	  write_from_exactly alert_out record.record_content 0 (String.length record.record_content)
	| _ -> fail (Failure "??")
    end >>= fun () ->
    timed_read_answers ()
  and timed_read_answers () =
    let t = read_answers () in
    pick [t; Lwt_unix.sleep 3.0 >>= fun () -> return None]
  in

  let rec parse_hs_msgs () =
    lwt_parse_handshake_msg ~context:(Some ctx) hs_lwt_in >>= fun hs_msg ->
    match handle_hs hs_msg with
      | None -> parse_hs_msgs ()
      | Some x -> return (Some x)
  in

  let rec parse_alert_msgs () =
    lwt_parse_tls_alert alert_lwt_in >>= fun alert ->
    match handle_alert alert with
      | None -> parse_alert_msgs ()
      | Some x -> return (Some x)
  in

  let p1 = parse_hs_msgs ()
  and p2 = parse_alert_msgs () in
  pick [p1; p2; timed_read_answers ()]


let rec _really_write o s p l =
  Lwt_unix.write o s p l >>= fun n ->
  if l = n then
    Lwt.return ()
  else
    _really_write o s (p + n) (l - n)

let really_write o s = _really_write o s 0 (String.length s)


let write_record o record =
  let s = dump_tls_record record in
  really_write o s



let print_hs hs =
  print_endline (print_handshake_msg "" "Handshake" hs);
  if hs.handshake_type = HT_ServerHelloDone
  then Some ()
  else None

let print_cs hs =
  match hs.handshake_content with
    | ServerHello { ciphersuite = cs } ->
      print_endline (string_of_ciphersuite cs);
      Some cs
    | _ -> None

let print_alert alert =
  print_endline (print_tls_alert "" "Alert" alert);
  if alert.alert_level = AL_Fatal
  then Some ()
  else None

let do_nothing _ = None





let remote_addr =
  let host_entry = Unix.gethostbyname "dev.yeye.fr" in
  let inet_addr = host_entry.Unix.h_addr_list.(0) in
  Unix.ADDR_INET (inet_addr, 443)

let send_and_receive v cs addr hs_fun alert_fun =
  let s = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  let ch = mk_client_hello v cs in
  Lwt_unix.connect s addr >>= fun () ->
  write_record s ch >>= fun () ->
  handle_answer hs_fun alert_fun (input_of_fd "Server" s)


let main_simple_probe addr suites =
  send_and_receive V_TLSv1_2 suites addr print_hs print_alert


let ssl_scan addr suites =
  let rec next_step s =
    send_and_receive V_TLSv1 s addr print_cs do_nothing >>= fun res ->
    match res with
      | None -> return []
      | Some suite_selected ->
	let next_suites = List.filter (fun x -> x <> suite_selected) s in
	if next_suites = []
	then return [suite_selected]
	else begin
	  next_step next_suites >>= fun r ->
	  return (suite_selected::r)
	end
  in next_step suites


let _ =
  Lwt_unix.run (main_simple_probe remote_addr [TLS_RSA_EXPORT_WITH_RC4_40_MD5; TLS_RSA_WITH_RC4_128_SHA; TLS_DHE_RSA_WITH_AES_128_CBC_SHA])
(*  Lwt_unix.run (ssl_scan remote_addr [TLS_RSA_EXPORT_WITH_RC4_40_MD5; TLS_RSA_WITH_RC4_128_SHA; TLS_DHE_RSA_WITH_AES_128_CBC_SHA; TLS_RSA_WITH_AES_256_CBC_SHA]) *)
