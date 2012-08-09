open Lwt
open Lwt_io
open Unix
open Getopt

open ParsingEngine
open DumpingEngine
open LwtParsingEngine
open TlsEnums
open Tls
open TlsEngine



(* Option handling *)

let verbose = ref false
let host = ref "www.google.com"
let port = ref 443
let rec_version = ref V_TLSv1
let ch_version = ref V_TLSv1
let suites = ref [TLS_RSA_WITH_RC4_128_SHA]
let compressions = ref [CM_Null]

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

let clear_compressions () = compressions := []
let add_compression s =
  try
    compressions := (compression_method_of_string s)::(!compressions);
    ActionDone
  with _ -> ShowUsage (Some "Invalid compression method")
let all_compressions () =
  let rec aux accu = function
    | 0x100 -> accu
    | n -> begin
      match compression_method_of_int n with
	| CM_UnknownVal _ -> aux accu (n+1)
	| cm -> aux (cm::accu) (n+1)
    end
  in
  compressions := aux [] 0
let rev_compressions () = compressions := List.rev (!compressions)

let update_version r s = r := tls_version_of_string s; ActionDone
let update_both_versions s =
  rec_version := tls_version_of_string s;
  ch_version := tls_version_of_string s;
  ActionDone

let options = [
  mkopt (Some 'h') "help" Usage "show this help";
  mkopt (Some 'v') "verbose" (Set verbose) "print more info to stderr";

  mkopt (Some 'H') "host" (StringVal host) "host to contact";
  mkopt (Some 'p') "port" (IntVal port) "port to probe";

  mkopt (Some 'V') "version" (StringFun update_both_versions) "set the record and ClientHello versions";
  mkopt None "record-version" (StringFun (update_version rec_version)) "set the record versions";
  mkopt None "client-hello-version" (StringFun (update_version ch_version)) "set the ClientHello versions";

  mkopt (Some 'C') "clear-suites" (TrivialFun clear_suites) "reset the list of suites";
  mkopt (Some 'A') "add-suite" (StringFun add_suite) "add a suite to the list of suites";
  mkopt None "all-suites" (TrivialFun all_suites) "add all the known suites";

  mkopt None "clear-compressions" (TrivialFun clear_compressions) "reset the list of compresion methods";
  mkopt None "add-compression" (StringFun add_compression) "add a suite to the list of compresion methods";
  mkopt None "all-compressions" (TrivialFun all_compressions) "add all the known compression methods";

  mkopt None "record-size" (IntVal plaintext_chunk_size) "set the size of the records sent";
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
	compression_methods = !compressions;
	client_extensions = exts
      }
    }
  }


let catch_eof = function
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
    lwt_parse_tls_record s >>= fun record ->
    let result = match record.content_type with
      | CT_Handshake ->
	append_to_input hs_in (dump_record_content record.record_content);
	process_input (parse_handshake_msg ~context:(Some ctx)) (handle_hs ctx) hs_in
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

  catch timed_read_answers catch_eof



let print_hs ctx hs =
  print_endline (print_handshake_msg "" "Handshake (S->C)" hs);
  match hs.handshake_type, hs.handshake_content with
  | HT_ServerHelloDone, _ -> Result ()
  | _, ServerHello { ciphersuite = cs } ->
    ctx.future.s_ciphersuite <- find_csdescr cs;
    NothingSoFar
  | _ -> NothingSoFar

let get_cs _ hs =
  match hs.handshake_content with
    | ServerHello { ciphersuite = cs } -> Result cs
    | _ -> NothingSoFar

let get_cm _ hs =
  match hs.handshake_content with
    | ServerHello { compression_method = cm } -> Result cm
    | _ -> NothingSoFar

let get_sh_version _ hs =
  match hs.handshake_content with
    | ServerHello { server_version = v } -> Result v
    | _ -> NothingSoFar

let stop_on_fatal_alert alert =
  if alert.alert_level = AL_Fatal
  then FatalAlert (string_of_tls_alert_type alert.alert_type)
  else NothingSoFar

let print_alert alert =
  print_endline (print_tls_alert "" "Alert (S->C)" alert);
  if alert.alert_level = AL_Fatal
  then FatalAlert (string_of_tls_alert_type alert.alert_type)
  else NothingSoFar

let do_nothing _ = NothingSoFar



let _send_and_receive hs_fun alert_fun =
  Util.client_socket ~timeout:(Some !timeout) !host !port >>= fun s ->
  if !verbose then Printf.fprintf Pervasives.stderr "Connected to %s:%d\n" !host !port;
  let ch = mk_client_hello None in
  if !verbose then prerr_endline (print_tls_record "" "Sending Handshake (C->S)" ch);
  send_plain_record s ch >>= fun () ->
  handle_answer hs_fun alert_fun (input_of_fd "Server" s)

let send_and_receive hs_fun alert_fun =
  catch (fun () -> _send_and_receive hs_fun alert_fun) catch_exceptions


let remove_from_list list elt =
  list := List.filter (fun x -> x <> elt) !list;
  !list <> []

let ssl_scan get to_string update =
  let rec next_step () =
    send_and_receive get stop_on_fatal_alert >>= fun res ->
    match res with
      | Result r ->
	if update r then begin
	  next_step () >>= fun other_res ->
	  match other_res with
	    | Result others -> return (Result ((to_string r)::others))
	    | _ -> return (Result [to_string r])
	end else return (Result [to_string r])
      | NothingSoFar -> return (Result [])
      | Timeout -> return (Result ["Timeout"])
      | EndOfFile -> return (Result ["EndOfFile"])
      | FatalAlert s -> return (Result ["FatalAlert \"" ^ s ^ "\""])
  in next_step ()

let ssl_scan_versions () =
  let versions = [V_SSLv3; V_TLSv1; V_TLSv1_1; V_TLSv1_2; V_Unknown 0x3ff] in
  let rec mk_versions ext int = match ext, int with
    | [], _ -> []
    | e::r, [] -> mk_versions r versions
    | e::_, i::s -> (e, i)::(mk_versions ext s)
  in
  let all_cases = mk_versions versions versions in

  let rec next_step = function
    | [] -> return (Result "")
    | (e, i)::r ->
      rec_version := e;
      ch_version := i;
      send_and_receive get_sh_version stop_on_fatal_alert >>= fun res ->
      let str_res = match res with
	| Result r -> string_of_tls_version r;
	| NothingSoFar -> "???"
	| Timeout -> "Timeout"
	| EndOfFile -> "EndOfFile"
	| FatalAlert s -> "FatalAlert \"" ^ s ^ "\""
      in
      Printf.printf "%s,%s -> %s\n" (string_of_tls_version e) (string_of_tls_version i) str_res;
      next_step r
  in next_step all_cases

let print_list = List.iter print_endline

let print_result print_fun = function
  | Result r -> print_fun r
  | NothingSoFar -> prerr_endline "NothingSoFar"
  | Timeout -> prerr_endline "Timeout"
  | EndOfFile -> prerr_endline "EndOfFile"
  | FatalAlert s -> prerr_endline ("FatalAlert \"" ^ s ^ "\"")


let _ =
  let args = parse_args getopt_params Sys.argv in
  match args with
    | ["scan-suites"] -> print_result print_list (Lwt_unix.run (ssl_scan get_cs string_of_ciphersuite (remove_from_list suites)))
    | ["scan-compressions"] -> print_result print_list (Lwt_unix.run (ssl_scan get_cm string_of_compression_method (remove_from_list compressions)))
    | ["scan-versions"] -> print_result ignore (Lwt_unix.run (ssl_scan_versions ()))
    | ["probe"] | [] -> print_result ignore (Lwt_unix.run (send_and_receive print_hs print_alert))
    | _ -> failwith "Invalid command"
