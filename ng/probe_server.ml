open Lwt
open Lwt_io
open Unix
open Getopt

open ParsingEngine
open DumpingEngine
open LwtParsingEngine
open TlsEnums
open TlsContext
open Tls
open TlsEngine


(* TODO:
   - Add a --retry option
   - Handle errors more smoothly
   - Add extensions
*)


(* Option handling *)

let verbose = ref false
let chunk_size = ref 1400
let host = ref "www.google.com"
let port = ref 443
let rec_version = ref V_TLSv1
let ch_version = ref V_TLSv1
let suites = ref [TLS_RSA_WITH_RC4_128_SHA]
let timeout = ref 3.0

let clear_suites () = suites := []
let add_suite s =
  try
    suites := (ciphersuite_of_string s)::(!suites);
    ActionDone
  with _ -> ShowUsage (Some "Invalid ciphersuite")
let all_suites () =
  let rec aux accu = function
    | 0x10000 -> accu
    | n -> begin
      match ciphersuite_of_int n with
	| TLS_UnknownSuite _ -> aux accu (n+1)
	| s -> aux (s::accu) (n+1)
    end
  in
  suites := aux [] 0
let rev_suites () = suites := List.rev (!suites)

let update_version r s = r := tls_version_of_string s; ActionDone
let update_both_versions s =
  ignore (update_version rec_version s);
  update_version ch_version s


let options = [
  mkopt (Some 'h') "help" Usage "show this help";
  mkopt (Some 'v') "verbose" (Set verbose) "print more info to stderr";
  mkopt (Some 'H') "host" (StringVal host) "host to contact";
  mkopt (Some 'p') "port" (IntVal port) "port to probe";
  mkopt (Some 'V') "version" (StringFun update_both_versions) "sets the record and ClientHello versions";
  mkopt None "record-version" (StringFun (update_version rec_version)) "sets the record versions";
  mkopt None "client-hello-version" (StringFun (update_version ch_version)) "sets the ClientHello versions";
  mkopt None "record-size" (IntVal chunk_size) "sets the size of the records sent";
  mkopt (Some 'C') "clear-suites" (TrivialFun clear_suites) "reset the list of suites";
  mkopt (Some 'A') "add-suite" (StringFun add_suite) "add a suite to the list of suites";
  mkopt None "all-suites" (TrivialFun all_suites) "add all the known suites";
  mkopt (Some 't') "timeout" (FloatVal timeout) "set the timeout";
]

let getopt_params = {
  default_progname = "probe_server";
  options = options;
  postprocess_funs = [rev_suites];
}



(* Useful functions *)

let mk_client_hello exts =
  {
    content_type = CT_Handshake;
    record_version = !rec_version;
    record_content = Handshake {
      handshake_type = HT_ClientHello;
      handshake_content = ClientHello {
	client_version = !ch_version;
	client_random = String.make 32 '\x00';
	client_session_id = "";
	ciphersuites = !suites;
	compression_methods = [CM_Null];
	client_extensions = exts
      }
    }
  }


let write_exactly o record_contet =
  let s = dump_record_content record_contet in
  write_from_exactly  o s 0 (String.length s)

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
	| CT_Handshake -> write_exactly hs_out record.record_content
	| CT_Alert -> write_exactly alert_out record.record_content
	| _ -> fail (Failure "??")
    end >>= fun () ->
    timed_read_answers ()
  and timed_read_answers () =
    let t = read_answers () in
    pick [t; Lwt_unix.sleep !timeout >>= fun () -> return None]
  in

  let rec parse_hs_msgs () =
    lwt_parse_handshake_msg ~context:(Some ctx) hs_lwt_in >>= fun hs_msg ->
    match handle_hs ctx hs_msg with
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

let write_record_by_chunks o record size =
  let recs = TlsUtil.split_record record size in
  Lwt_list.iter_s (write_record o) recs


let print_hs ctx hs =
  print_endline (print_handshake_msg "" "Handshake (S->C)" hs);
  match hs.handshake_type, hs.handshake_content with
  | HT_ServerHelloDone, _ -> Some ()
  | _, ServerHello { ciphersuite = cs } ->
    ctx.future.s_ciphersuite <- cs;
    None
  | _ -> None

let print_cs _ hs =
  match hs.handshake_content with
    | ServerHello { ciphersuite = cs } ->
      print_endline (string_of_ciphersuite cs);
      Some cs
    | _ -> None

let print_alert alert =
  print_endline (print_tls_alert "" "Alert (S->C)" alert);
  if alert.alert_level = AL_Fatal
  then Some ()
  else None

let do_nothing _ = None



let mk_remote_addr host port =
  let host_entry = Unix.gethostbyname host in
  let inet_addr = host_entry.Unix.h_addr_list.(0) in
  Unix.ADDR_INET (inet_addr, port)



let send_and_receive (host, port) hs_fun alert_fun =
  let s = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  let addr = mk_remote_addr host port in
  Lwt_unix.connect s addr >>= fun () ->
  if !verbose then Printf.fprintf Pervasives.stderr "Connected to %s:%d\n" host port;
  let ch = mk_client_hello None in
  if !verbose then prerr_endline (print_tls_record "" "Sending Handshake (C->S)" ch);
  write_record_by_chunks s ch !chunk_size >>= fun () ->
  handle_answer hs_fun alert_fun (input_of_fd "Server" s)


let main_simple_probe addr =
  send_and_receive addr print_hs print_alert


let ssl_scan addr =
  let rec next_step () =
    send_and_receive addr print_cs do_nothing >>= fun res ->
    match res with
      | None -> return []
      | Some suite_selected ->
	let next_suites = List.filter (fun x -> x <> suite_selected) !suites in
	if next_suites = []
	then return [suite_selected]
	else begin
	  suites := next_suites;
	  next_step () >>= fun r ->
	  return (suite_selected::r)
	end
  in next_step ()




let _ =
  let args = parse_args getopt_params Sys.argv in
  let remote_addr = (!host, !port) in
  match args with
    | ["scan"] -> ignore (Lwt_unix.run (ssl_scan remote_addr))
    | ["probe"] | [] -> ignore (Lwt_unix.run (main_simple_probe remote_addr))
    | _ -> failwith "Invalid command"
