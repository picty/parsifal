open Lwt
open Lwt_io
open LwtUtil
open Unix
open Getopt

open Parsifal
open TlsEnums
open Tls



(* Copy/paste from old TlsEngine *)

let plaintext_chunk_size = ref 16384
let timeout = ref 3.0

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
  let ctx = empty_context default_prefs in

  let process_input parse_fun handle_fun input =
    match try_parse parse_fun input with
      | None -> NothingSoFar, input
      | Some parsed_msg ->
	let res = handle_fun parsed_msg in
	let new_input = drop_used_string input in
	res, new_input
  in

  let rec read_answers hs_in alert_in =
    lwt_parse_wrapper (parse_tls_record None) s >>= fun record ->
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

(* End of Copy/paste from old TlsEngine *)



(* Option handling *)

let verbose = ref false
let base64 = ref true
let host = ref "www.google.com"
let port = ref 443
let rec_version = ref V_TLSv1
let ch_version = ref V_TLSv1
let suites = ref [TLS_RSA_WITH_RC4_128_SHA]
let compressions = ref [CM_Null]
let retry = ref 3

let clear_suites () = suites := []
let add_suite s =
  try
    suites := (!suites)@[ciphersuite_of_string s];
    ActionDone
  with _ -> ShowUsage (Some "Invalid ciphersuite")
let all_suites () =
  let rec aux accu = function
    | 0x10000 -> List.rev accu
    | n -> begin
      match ciphersuite_of_int n with
	| TLS_UnknownSuite _ -> aux accu (n+1)
	| s -> aux (s::accu) (n+1)
    end
  in
  suites := aux [] 0

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

let deep_parse () =
  enrich_certificate_in_certificates := true;
  enrich_distinguishedName_in_certificate_request := true

let options = [
  mkopt (Some 'h') "help" Usage "show this help";
  mkopt (Some 'v') "verbose" (Set verbose) "print more info to stderr";
  mkopt None "pem" (Set base64) "use PEM format (default)";
  mkopt None "der" (Clear base64) "use DER format";

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
  mkopt None "retry" (IntVal retry) "set the number of tentatives";

  mkopt None "deep-parse" (TrivialFun deep_parse) "activate deep parsing for certificates/DNs";
]



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

let global_hs_msg = ref []

let print_hs ctx hs =
  print_endline (print_value ~name:"Handshake (S->C)" (value_of_handshake_msg hs));
  global_hs_msg := hs::(!global_hs_msg);
  match hs.handshake_type, hs.handshake_content with
  | HT_ServerHelloDone, _ -> Result ()
  | _, ServerHello { ciphersuite = cs } ->
    ctx.future.proposed_ciphersuites <- [cs];
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

let get_certs _ hs =
  match hs.handshake_content with
  | Certificate certs -> Result certs
  | _ -> NothingSoFar

let stop_on_fatal_alert alert =
  if alert.alert_level = AL_Fatal
  then FatalAlert (string_of_tls_alert_type alert.alert_type)
  else NothingSoFar

let print_alert alert =
  print_endline (print_value ~name:"Alert (S->C)" (value_of_tls_alert alert));
  if alert.alert_level = AL_Fatal
  then FatalAlert (string_of_tls_alert_type alert.alert_type)
  else NothingSoFar

let do_nothing _ = NothingSoFar



let _send_and_receive hs_fun alert_fun =
  client_socket ~timeout:(Some !timeout) !host !port >>= fun s ->
  if !verbose then Printf.fprintf Pervasives.stderr "Connected to %s:%d\n" !host !port;
  let ch = mk_client_hello None in
  if !verbose then prerr_endline (print_value ~name:"Sending Handshake (C->S)" (value_of_tls_record ch));
  send_plain_record s ch >>= fun () ->
  input_of_fd "Server" s >>=
  handle_answer hs_fun alert_fun

let rec send_and_receive retry hs_fun alert_fun =
  catch (fun () -> _send_and_receive hs_fun alert_fun) (catch_exceptions retry) >>= function
  | Retry ->
    if !verbose then prerr_endline "Connection failed... retrying";
    send_and_receive (retry - 1) hs_fun alert_fun
  | res -> return res


let remove_from_list list elt =
  list := List.filter (fun x -> x <> elt) !list;
  !list <> []

let ssl_scan get to_string update =
  let rec next_step () =
    send_and_receive !retry get stop_on_fatal_alert >>= fun res ->
    match res with
      | Result r ->
	if update r then begin
	  next_step () >>= fun other_res ->
	  match other_res with
	    | Result others -> return (Result ((to_string r)::others))
	    | _ -> return (Result [to_string r])
	end else return (Result [to_string r])
      | Retry | NothingSoFar -> return (Result [])
      | Timeout -> return (Result ["Timeout"])
      | EndOfFile -> return (Result ["EndOfFile"])
      | FatalAlert s -> return (Result ["FatalAlert \"" ^ s ^ "\""])
  in next_step ()

let ssl_scan_versions () =
  let versions = [V_SSLv3; V_TLSv1; V_TLSv1_1; V_TLSv1_2; V_Unknown 0x3ff] in
  let rec mk_versions ext int = match ext, int with
    | [], _ -> []
    | _::r, [] -> mk_versions r versions
    | e::_, i::s -> (e, i)::(mk_versions ext s)
  in
  let all_cases = mk_versions versions versions in

  let rec next_step = function
    | [] -> return (Result "")
    | (e, i)::r ->
      rec_version := e;
      ch_version := i;
      send_and_receive !retry get_sh_version stop_on_fatal_alert >>= fun res ->
      let str_res = match res with
	| Result r -> string_of_tls_version r;
	| Retry | NothingSoFar -> "???"
	| Timeout -> "Timeout"
	| EndOfFile -> "EndOfFile"
	| FatalAlert s -> "FatalAlert \"" ^ s ^ "\""
      in
      Printf.printf "%s,%s -> %s\n" (string_of_tls_version e) (string_of_tls_version i) str_res;
      next_step r
  in next_step all_cases

let print_list = List.iter print_endline

let save_certs certs =
  let ext = if !base64 then ".pem" else ".der" in
  let rec save_one_cert i = function
    | cert::r ->
      let f = open_out (!host ^ "-" ^ (string_of_int i) ^ ext) in
      let buf = POutput.create () in
      let dump_cert = PTypes.dump_trivial_union X509.dump_certificate in
      let dump_fun =
	if !base64
	then Base64.dump_base64_container (Base64.HeaderInList ["CERTIFICATE"]) dump_cert
	else dump_cert
      in dump_fun buf cert;
      POutput.output_buffer f buf;
      close_out f;
      save_one_cert (i+1) r
    | [] -> i
  in
  let n_certs = save_one_cert 0 certs in
  Printf.printf "Saved %d certificates\n" n_certs


let print_result print_fun = function
  | Result r -> print_fun r
  | Retry -> prerr_endline "Retry ?!"
  | NothingSoFar -> prerr_endline "NothingSoFar"
  | Timeout -> prerr_endline "Timeout"
  | EndOfFile -> prerr_endline "EndOfFile"
  | FatalAlert s -> prerr_endline ("FatalAlert \"" ^ s ^ "\"")


let _ =
  let args = parse_args ~progname:"probe_server" options Sys.argv in
  match args with
    | ["scan-suites"] -> print_result print_list (Lwt_unix.run (ssl_scan get_cs string_of_ciphersuite (remove_from_list suites)))
    | ["scan-compressions"] -> print_result print_list (Lwt_unix.run (ssl_scan get_cm string_of_compression_method (remove_from_list compressions)))
    | ["scan-versions"] -> print_result ignore (Lwt_unix.run (ssl_scan_versions ()))
    | ["probe"] | [] -> print_result ignore (Lwt_unix.run (send_and_receive !retry print_hs print_alert))
    | ["extract-certificates"]
    | ["extract-certs"] -> print_result save_certs (Lwt_unix.run (send_and_receive !retry get_certs stop_on_fatal_alert))
    | _ -> failwith "Invalid command"
