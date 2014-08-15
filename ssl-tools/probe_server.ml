open Lwt
open Lwt_io
open LwtUtil
open Unix
open Getopt

open Parsifal
open TlsEnums
open Tls
open TlsEngineNG


(* TODO: Merge connection_options and prefs? *)
(* TODO: Handle SSLv2 => merge TLS and SSLv2 ciphersuite in TlsEnums? *)


(*******************)
(* Option handling *)
(*******************)

let verbose = ref false
let base64 = ref true
let host = ref "www.google.com"
let port = ref 443
let rec_version = ref V_TLSv1
let ch_version = ref V_TLSv1
let suites = ref [TLS_RSA_WITH_RC4_128_SHA]
let compressions = ref [CM_Null]
let plaintext_chunk_size = ref 16384
let timeout = ref 3.0
(* TODO? *)
(* let retry = ref 3 *)
let cas = ref []


(* TODO: Add stuff to add/remove/clear a list in getopt? *)

let remove_from_list list elt =
  list := List.filter (fun x -> x <> elt) !list;
  !list <> []

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

let add_ca filename =
  cas := filename::!cas;
  ActionDone

let output_file = ref ""


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
  (* TODO *)
(*  mkopt None "retry" (IntVal retry) "set the number of tentatives"; *)

  mkopt None "deep-parse" (TrivialFun deep_parse) "activate deep parsing for certificates/DNs";

  mkopt None "ca" (StringFun add_ca) "select a CA file";

  mkopt (Some 'o') "output" (StringVal output_file) "select an output file";
]

(* TODO: Move this code to getopt? *)

type probe_cmd =
| ProbeAndPrint
| ScanSuites
| ScanCompressions
| ScanVersions
| ExtractCerts
| CheckCerts
| ProbeToDump

let probe_cmd_args = [
  "probe2dump", ProbeToDump;
  "probe", ProbeAndPrint;
  "scan-suites", ScanSuites;
  "scan-compressions", ScanCompressions;
  "scan-versions", ScanVersions;
  "extract-certs", ExtractCerts;
  "check-certs", CheckCerts;
]

let cmd_of_args = function
  | [s] ->
    begin
      try List.assoc s probe_cmd_args
      with Not_found -> usage "probe_server" options
	(Some ("Invalid command. Please use one of the following commands: " ^
		  (String.concat "\n" (List.map fst probe_cmd_args))))
    end
  | _ -> usage "probe_server" options
    (Some ("Please use one of the following commands: " ^
	(String.concat ", " (List.map fst probe_cmd_args))))




(*********************)
(* Probing automaton *)
(*********************)

type probe_state =
| NothingSoFar
| Fatal of string

let probe_automata (msgs_received, _) input _global_ctx ctx =
  match input with
  | InputTlsMsg ({ record_content = Handshake { handshake_content = hs_msg } } as m) ->
    let action = match hs_msg with
      | ServerHello sh -> update_with_server_hello ctx sh; Wait
      | Certificate certs -> update_with_certificate ctx certs; Wait
      | ServerKeyExchange ske -> update_with_server_key_exchange ctx ske; Wait
      | ServerHelloDone -> FatalAlert AT_CloseNotify
      | _ -> Wait
    in
    (m::msgs_received, NothingSoFar), action
  | InputTlsMsg ({ record_content = Alert { alert_level = AL_Fatal; alert_type = at } } as m) ->
    (m::msgs_received, Fatal (string_of_tls_alert_type at)), Abort
  | InputTlsMsg m -> (m::msgs_received, NothingSoFar), Wait

  | InputSSL2Msg _ ->
    (msgs_received, Fatal "Unexpected SSLv2 message"), FatalAlert AT_HandshakeFailure
  | Timeout ->
    (msgs_received, Fatal "Timeout"), FatalAlert AT_CloseNotify
  | EndOfFile ->
    (msgs_received, Fatal "EndOfFile"), FatalAlert AT_CloseNotify

  | Nothing -> (msgs_received, NothingSoFar), Wait
  | InternalMsgIn _ -> (msgs_received, NothingSoFar), Wait

let probe_server prefs server port =
  let ctx = empty_context prefs in
  let c_opts = {
    verbose = !verbose; timeout = Some !timeout;
    plaintext_chunk_size = !plaintext_chunk_size;
  } in
  init_client_connection ~options:c_opts server port >>= fun c_sock ->
  if !verbose then Printf.fprintf Pervasives.stderr "Connected to %s:%d\n" server port;
  let ch = mk_client_hello ctx in
  if !verbose then prerr_endline (print_value ~name:"Sending Handshake (C->S)" (value_of_tls_record ch));
  c_sock.output <- exact_dump dump_tls_record ch;
  run_automata probe_automata ([], NothingSoFar) "" ctx c_sock >>= fun (msgs, res) ->
  Lwt_unix.close c_sock.socket >>= fun () ->
  let remaining_str = BasePTypes.parse_rem_binstring c_sock.input in
  return (ctx, msgs, remaining_str, res)



let save_certs certs =
  let ext = if !base64 then ".pem" else ".der" in
  let rec save_one_cert i = function
    | cert::r ->
      let cert_name = !host ^ "-" ^ (string_of_int i) ^ ext in
      let f =
	try open_out_gen [Open_wronly; Open_creat; Open_excl] 0o644 cert_name
	with _ -> failwith ("Unable to create file: " ^ cert_name)
      in
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


let _ =
  try
    TlsDatabase.enrich_suite_hash ();
    let args = parse_args ~progname:"probe_server" options Sys.argv in
    let cmd = cmd_of_args args in
    let prefs = {
      random_generator = RandomEngine.default_random_generator ();
      acceptable_versions = (!rec_version, !ch_version);
      acceptable_ciphersuites = !suites;
      acceptable_compressions = !compressions;
      directive_behaviour = false;
      available_certificates = []
    } in
    match cmd with
    | ProbeAndPrint ->
      let _, msgs, _, res = Lwt_unix.run (probe_server prefs !host !port) in
      let print_msg msg = print_endline (print_value ~name:"TLS Record (S->C)" (value_of_tls_record msg)) in
      List.iter print_msg (List.rev msgs);
      begin
	match res with
	| NothingSoFar -> ()
	| Fatal msg -> print_endline msg
      end
    | ProbeToDump ->
      let output_result = match !output_file with
        | "" -> (fun buf -> print_endline (hexdump (POutput.contents buf)))
        | fn ->
          let f =
            try open_out_gen [Open_wronly; Open_creat; Open_excl] 0o644 fn
            with _ -> failwith ("Unable to create file: " ^ fn)
          in
          (fun buf -> POutput.output_buffer f buf; close_out f)
      in
      (* Handle SSLv2 answers? *)
      let _, msgs, remaining_stuff, _ = Lwt_unix.run (probe_server prefs !host !port) in
      let content_to_dump = POutput.create () in
      List.iter (dump_tls_record content_to_dump) (List.rev msgs);
      POutput.add_string content_to_dump remaining_stuff;
      let open AnswerDump in
      let answer_dump = {
	ip_type = 4; (* TODO *)
	ip_addr = AD_IPv4 "\x00\x00\x00\x00"; (* TODO *)
	port = !port;
	name = !host;
	campaign = 0xff;  (* TODO *)
	msg_type = 0;
	timestamp = Int64.of_float (Unix.time ());
	content = POutput.contents content_to_dump;
      } in
      let final_output = POutput.create () in
      dump_answer_dump_v2 final_output answer_dump;
      output_result final_output
    | ExtractCerts ->
      let ctx, _, _, _ = Lwt_unix.run (probe_server prefs !host !port) in
      save_certs ctx.future.f_certificates
    | CheckCerts ->
      let ca_store = X509Util.mk_cert_store 100 in
      let ctx, _, _, _ = Lwt_unix.run (probe_server prefs !host !port) in
      let parse_root_ca c =
	let parse_fun = if !base64
	  then Base64.parse_base64_container Base64.AnyHeader "base64_container" (X509Util.parse_smart_cert true)
	  else (X509Util.parse_smart_cert true)
	in
	let sc = parse_fun (string_input_of_filename c) in
	X509Util.add_to_store ca_store sc
      in
      List.iter parse_root_ca (List.rev !cas);
      let parsed_certs = List.mapi
	(X509Util.sc_of_cert_in_hs_msg false (!host ^ ":" ^ (string_of_int !port)))
	ctx.future.f_certificates
      in
      List.iter (fun c -> print_endline (X509Util.rate_chain c); X509Util.print_chain c; print_newline ())
	(X509Util.build_certchain parsed_certs ca_store)

    | ScanSuites ->
      let rec next_step () =
	let updated_prefs = { prefs with acceptable_ciphersuites = !suites } in
	let ctx, _, _, res = Lwt_unix.run (probe_server updated_prefs !host !port) in
	match res, ctx.future.proposed_ciphersuites with
	| NothingSoFar, [s] ->
	  print_endline (string_of_ciphersuite s);
	  if remove_from_list suites s then next_step ()
	| NothingSoFar, _ -> if !verbose then prerr_endline "Unexpected result."
	| Fatal msg, _ -> if !verbose then prerr_endline msg
      in
      next_step ()
    | ScanCompressions ->
      let rec next_step () =
	let updated_prefs = { prefs with acceptable_compressions = !compressions } in
	let ctx, _, _, res = Lwt_unix.run (probe_server updated_prefs !host !port) in
	match res, ctx.future.proposed_compressions with
	| NothingSoFar, [c] ->
	  print_endline (string_of_compression_method c);
	  if remove_from_list compressions c then next_step ()
	| NothingSoFar, _ -> if !verbose then prerr_endline "Unexpected result."
	| Fatal msg, _ -> if !verbose then prerr_endline msg
      in
      next_step ()
    | ScanVersions ->
      let versions = [V_SSLv3; V_TLSv1; V_TLSv1_1; V_TLSv1_2; V_Unknown 0x3ff] in
      let rec mk_versions ext int = match ext, int with
	| [], _ -> []
	| _::r, [] -> mk_versions r versions
	| e::_, i::s -> (e, i)::(mk_versions ext s)
      in
      let all_cases = mk_versions versions versions in

      let rec next_step = function
	| [] -> ()
	| (e, i)::r ->
	  let updated_prefs = { prefs with acceptable_versions = (e, i) } in
	  let ctx, _, _, res = Lwt_unix.run (probe_server updated_prefs !host !port) in
	  match res, ctx.future.proposed_versions with
	  | NothingSoFar, (v1, v2) ->
	    if v1 <> v2 then begin
	      if !verbose then prerr_endline "Unexpected result."
	    end else begin
	      Printf.printf "%s,%s -> %s\n" (string_of_tls_version e)
		(string_of_tls_version i) (string_of_tls_version v1);
	      next_step r
	    end
	  | Fatal msg, _ -> if !verbose then prerr_endline msg
      in next_step all_cases
  with
    | End_of_file -> ()
    | ParsingException (e, h) -> prerr_endline (string_of_exception e h); exit 1
    | e -> prerr_endline (Printexc.to_string e)
