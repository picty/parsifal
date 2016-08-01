open Lwt
open Lwt_io
open LwtUtil
open Unix
open Getopt

open Parsifal
open TlsEnums
open Ssl2
open Tls
open TlsEngineNG


(* TODO: Merge connection_options and prefs? *)
(* TODO: Handle SSLv2 => merge TLS and SSLv2 ciphersuite in TlsEnums? *)


(*******************)
(* Option handling *)
(*******************)

(* TODO: Move this into a generic framework? *)
type debug_level = Quiet | InfoDebug | FullDebug
let debug_level = ref Quiet
let set_debug_level = function
  | 0 -> debug_level := Quiet; ActionDone
  | 1 -> debug_level := InfoDebug; ActionDone
  | 2 -> debug_level := FullDebug; ActionDone
  | _ -> ShowUsage (Some "Wrong debug level (acceptable valuse are 0 - quiet, 1 - connections, 2 - messages)")
let int_of_debug_level = function
  | Quiet -> 0
  | InfoDebug -> 1
  | FullDebug -> 2
let (>=.) d1 d2 = (int_of_debug_level d1) >= (int_of_debug_level d2)

let base64 = ref true
let cas = ref []
let host_ref = ref "www.google.com"
let port_ref = ref 443

(* TLS preferences *)
let rec_version = ref V_TLSv1
let ch_version = ref V_TLSv1
let suites = ref [TLS_RSA_WITH_RC4_128_SHA]
let compressions = ref [CM_Null]
let use_extensions = ref true
let send_SNI = ref true
let extra_extensions = ref []
let plaintext_chunk_size = ref 16384
let timeout = ref 3.0
(* TODO? *)
(* let retry = ref 3 *)

(* probe2dump specific options *)
let hosts_file = ref ""
let campaign_number = ref 0xff
let max_inflight_requests = ref 1
let keep_empty_answers = ref false

(* TODO: Add stuff to add/remove/clear a list in getopt? *)
let remove_from_list list elt =
  let new_list = List.filter (fun x -> x <> elt) !list in
  if new_list <> !list then begin
    list := new_list;
    !list <> []
  end else false

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

let update_params_from_stimulus filename =
  let i = string_input_of_filename ~enrich:(AlwaysEnrich) filename in
  match try_parse (Tls.parse_tls_record None) i with
  | None ->
     begin
       match try_parse (Ssl2.parse_ssl2_record { Ssl2.cleartext = true }) i with
       | Some { ssl2_content = SSL2Handshake
                { ssl2_handshake_content = SSL2ClientHello ch } } ->
          rec_version := V_SSLv2;
          ch_version := ch.ssl2_client_version;
          suites := ch.ssl2_client_cipher_specs;
          compressions := [CM_Null];
          use_extensions := false;
          send_SNI := true;
          if !debug_level >=. InfoDebug
          then prerr_endline ("Parsed an SSLv2 stimulus from \"" ^ filename ^ "\"");
          ActionDone
       | _ -> ShowUsage (Some "Invalid stimulus")
     end
  | Some { record_version = rec_v;
           record_content = Handshake
           { handshake_content = ClientHello ch } } ->
     rec_version := rec_v;
     ch_version := ch.client_version;
     suites := ch.ciphersuites;
     compressions := ch.compression_methods;
     begin
       match ch.client_extensions with
       | None -> use_extensions := false
       | Some es ->
          use_extensions := true;
          let sni_ext, other_exts = List.partition (fun e -> e.extension_type = HE_ServerName) es in
          send_SNI := sni_ext != [];
          extra_extensions := other_exts;
     end;
     if !debug_level >=. InfoDebug
     then prerr_endline ("Parsed an SSLv3/TLS stimulus from \"" ^ filename ^ "\"");
     ActionDone
  | _ -> ShowUsage (Some "Invalid stimulus")


let options = [
  mkopt (Some 'h') "help" Usage "show this help";
  mkopt (Some 'q') "quiet" (TrivialFun (fun () -> debug_level := Quiet)) "print less info to stderr";
  mkopt (Some 'v') "verbose" (TrivialFun (fun () -> debug_level := FullDebug)) "print more info to stderr";
  mkopt None "laxist" (TrivialFun X509Util.relax_x509_constraints) "relax some constraints on certificate parsing";
  mkopt (Some 'd') "debug-level" (IntFun set_debug_level) "change the debug level (0-2)";

  mkopt None "pem" (Set base64) "use PEM format (default)";
  mkopt None "der" (Clear base64) "use DER format";

  mkopt (Some 'H') "host" (StringVal host_ref) "host to contact";
  mkopt None "hosts-file" (StringVal hosts_file) "set a list of hosts to probe (only for probe2dump)";
  mkopt (Some 'p') "port" (IntVal port_ref) "port to probe";

  mkopt (Some 'V') "version" (StringFun update_both_versions) "set the record and ClientHello versions";
  mkopt None "record-version" (StringFun (update_version rec_version)) "set the record versions";
  mkopt None "client-hello-version" (StringFun (update_version ch_version)) "set the ClientHello versions";

  mkopt None "stimulus" (StringFun update_params_from_stimulus) "set the parameters from a given stimulus";
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

  mkopt None "campaign" (IntVal campaign_number) "set the campaign number for dump outputs";
  mkopt (Some 'o') "output" (StringVal output_file) "select an output file (- for stdout in raw mode, nothing for hex mode)";
  mkopt None "max-parallel-requests" (IntVal max_inflight_requests) "set the maximum number of parallel threads";
  mkopt None "keep-empty-answers" (Set keep_empty_answers) "keep empty answers in the dump file";

  (* TODO: Add a shortcut in Getopt to handle with/without in one line *)
  mkopt None "with-extensions" (Set use_extensions) "activate the extension in the ClientHello (default)";
  mkopt None "without-extensions" (Clear use_extensions) "deactivate the extension in the ClientHello";
  mkopt None "with-SNI" (Set send_SNI) "send the Server Name Indication (default) (with-extensions must be set)";
  mkopt None "without-SNI" (Clear send_SNI) "do not send the Server Name Indication";
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
| ShowStimulus

let probe_cmd_args = [
  "probe2dump", ProbeToDump;
  "probe", ProbeAndPrint;
  "scan-suites", ScanSuites;
  "scan-compressions", ScanCompressions;
  "scan-versions", ScanVersions;
  "extract-certs", ExtractCerts;
  "check-certs", CheckCerts;
  "show-stimulus", ShowStimulus;
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


let get_sni_name ip hostname =
  match ip with
  | Some ip_value ->
    let ip_str = Unix.string_of_inet_addr ip_value in
    if ip_str = hostname then None else Some hostname
  | None -> Some hostname



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

let show_stimulus prefs (ip, server_name, _) =
  let server_names = match get_sni_name ip server_name with
    | None -> []
    | Some n -> [n]
  in
  let real_prefs = { prefs with server_names = server_names } in
  let ctx = empty_context real_prefs in
  let v =
    if fst real_prefs.acceptable_versions = V_SSLv2 then begin
      let ssl2_ch = mk_ssl2_client_hello ctx in
      value_of_ssl2_record ssl2_ch
    end else begin
      let ch = mk_client_hello ~extra_exts:!extra_extensions ctx in
      value_of_tls_record ch
    end
  in
  print_endline (print_value ~name:"Stimulus" v);
  return ()


let probe_server prefs ((ip, server_name, port) as server_params) =
  let server_names = match get_sni_name ip server_name with
    | None -> []
    | Some n -> [n]
  in
  let real_prefs = { prefs with server_names = server_names } in
  let ctx = empty_context real_prefs in
  let c_opts = {
    timeout = Some !timeout;
    plaintext_chunk_size = !plaintext_chunk_size;
  } in
  let probe_t () =
    init_client_connection ~options:c_opts server_params >>= fun c_sock ->
    let do_some_work () =
      if !debug_level >=. InfoDebug
      then prerr_endline ("Connected to " ^ server_name ^ ":" ^ (string_of_int port));
      if fst real_prefs.acceptable_versions = V_SSLv2 then begin
        let ssl2_ch = mk_ssl2_client_hello ctx in
        if !debug_level >=. FullDebug
        then prerr_endline (print_value ~name:"Sending Handshake (C->S)" (value_of_ssl2_record ssl2_ch));
        output_ssl2_record c_sock ssl2_ch;
      end else begin
        let ch = mk_client_hello ~extra_exts:!extra_extensions ctx in
        if !debug_level >=. FullDebug
        then prerr_endline (print_value ~name:"Sending Handshake (C->S)" (value_of_tls_record ch));
        output_record ctx c_sock (fun () -> ch);
      end;
      run_automata probe_automata ([], NothingSoFar) "" ctx c_sock >>= fun (msgs, res) ->
      let remaining_str = BasePTypes.parse_rem_binstring c_sock.input in
      return (ctx, msgs, remaining_str, res)
    in
    finalize do_some_work (fun () -> Lwt_unix.close c_sock.socket)
  and error_t = function
    | Unix.Unix_error (errno, syscall, additional) ->
      if !debug_level >=. InfoDebug
      then prerr_endline ("Unix error (" ^ Unix.error_message errno ^
                             ") during " ^ syscall ^ "(" ^ additional ^ ")");
      return (ctx, [], "", Fatal "UnixError")
    | ConnectionTimeout ->
      return (ctx, [], "", Fatal "ConnectionTimeout")
    | Not_found ->
      return (ctx, [], "", Fatal "NotFound")
    | e -> fail e
  in
  try_bind probe_t return error_t



let save_certs prefix certs =
  let ext = if !base64 then ".pem" else ".der" in
  let rec save_one_cert i = function
    | cert::r ->
      let cert_name = prefix ^ "-" ^ (string_of_int i) ^ ext in
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


let read_hosts_from_file hosts_file port =
  let f = open_in hosts_file in
  let rec read_aux accu =
    let line =
      try Some (input_line f)
      with End_of_file -> None
    in
    match line with
    | None -> List.rev accu
    | Some l ->
      let new_accu = match List.map String.trim (string_split ':' l) with
        | ["IP"; ip] -> (return (Some (Unix.inet_addr_of_string ip), ip, port))::accu
        | ["DNS"; server_name] -> (resolve server_name port)::accu
        | [] -> accu
        | s::_ ->
          if String.length s = 0 || s.[0] <> '#'
          then prerr_endline ("Invalid line in hosts file : " ^ (quote_string l) ^ ".");
	  accu
      in read_aux new_accu
  in
  read_aux []


let extract_cert_t prefs host_t =
  host_t >>= fun ((_, server_name, port) as server_params) ->
  probe_server prefs server_params >>= fun (ctx, _, _, _) ->
  return (server_name, port, ctx.future.f_certificates)


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
      use_extensions = !use_extensions;
      available_certificates = [];
      directive_behaviour = false;
      send_SNI = !send_SNI;
      server_names = [];
    } in

    let hosts_threads = match !hosts_file, !host_ref with
      | "", h -> [resolve h !port_ref]
      | hs, _ -> read_hosts_from_file hs !port_ref
    in

    match cmd, hosts_threads with
    | ProbeAndPrint, [host_t] ->
      let _, msgs, _, res = Lwt_unix.run (host_t >>= probe_server prefs) in
      let print_msg msg = print_endline (print_value ~name:"TLS Record (S->C)" (value_of_tls_record msg)) in
      List.iter print_msg (List.rev msgs);
      begin
	match res with
	| NothingSoFar -> ()
	| Fatal msg -> print_endline msg
      end
    | ExtractCerts, [host_t] ->
      let prefix, _, certs = Lwt_unix.run (extract_cert_t prefs host_t) in
      save_certs prefix certs
    | CheckCerts, [host_t] ->
      let ca_store = X509Util.mk_cert_store 100 in
      let server_name, port, certs = Lwt_unix.run (extract_cert_t prefs host_t) in
      let parse_root_ca c =
        let sc = X509Util.sc_of_input !base64 true (string_input_of_filename c) in
	X509Util.add_to_store ca_store sc
      in
      List.iter parse_root_ca (List.rev !cas);
      let parsed_certs = List.mapi
	(X509Util.sc_of_cert_in_hs_msg false (server_name ^ ":" ^ (string_of_int port)))
	certs
      in
      List.iter (fun c -> print_endline (X509Util.rate_chain c); X509Util.print_chain c; print_newline ())
	(X509Util.build_certchain None parsed_certs ca_store)

    | ScanSuites, [host_t] ->
      let rec next_step () =
	let updated_prefs = { prefs with acceptable_ciphersuites = !suites } in
	let ctx, _, _, res = Lwt_unix.run (host_t >>= probe_server updated_prefs) in
	match res, ctx.future.proposed_ciphersuites with
	| NothingSoFar, [s] ->
	  print_endline (string_of_ciphersuite s);
	  if remove_from_list suites s then next_step ()
	| NothingSoFar, _ -> if !debug_level >=. InfoDebug then prerr_endline "Unexpected result."
	| Fatal msg, _ -> if !debug_level >=. InfoDebug then prerr_endline msg
      in
      next_step ()
    | ScanCompressions, [host_t] ->
      let rec next_step () =
	let updated_prefs = { prefs with acceptable_compressions = !compressions } in
	let ctx, _, _, res = Lwt_unix.run (host_t >>= probe_server updated_prefs) in
	match res, ctx.future.proposed_compressions with
	| NothingSoFar, [c] ->
	  print_endline (string_of_compression_method c);
	  if remove_from_list compressions c then next_step ()
	| NothingSoFar, _ -> if !debug_level >=. InfoDebug then prerr_endline "Unexpected result."
	| Fatal msg, _ -> if !debug_level >=. InfoDebug  then prerr_endline msg
      in
      next_step ()
    | ScanVersions, [host_t] ->
      let versions = [V_SSLv3; V_TLSv1; V_TLSv1_1; V_TLSv1_2;
                      V_Unknown 0x304; V_Unknown 0x3ff] in
      let pad_to exp_len s =
        let s_len = String.length s in
        if exp_len <= s_len
        then String.sub s 0 exp_len
        else begin
          let padding = exp_len - s_len in
          let pad1 = padding / 2 and pad2 = (padding + 1) / 2 in
          (String.make pad1 ' ') ^ s ^ (String.make pad2 ' ')
        end
      in
      let string_of_version = function
        | V_Unknown x -> Printf.sprintf "0x%4.4x" x
        | v -> string_of_tls_version v
      in

      (* TODO: Print a cool tabular instead of those ugly lines *)
      let rec next_step accu exts ints = match exts, ints with
	| [], _ -> ()
        | e::es, [] ->
          let cells = (string_of_version e)::(List.rev accu) in
          print_endline (String.concat "|" (List.map (pad_to 12) cells));
          next_step [] es versions
        | e::_, i::is ->
	  let updated_prefs = { prefs with acceptable_versions = (e, i) } in
	  let ctx, _, _, res = Lwt_unix.run (host_t >>= probe_server updated_prefs) in
          let result_string = match res, ctx.future.proposed_versions with
	    | NothingSoFar, (v1, v2) ->
              if v1 <> v2 then "?!" else string_of_version v1
	    | Fatal msg, _ -> msg
          in next_step (result_string::accu) exts is
      in
      let headers = ""::(List.map string_of_version versions) in
      print_endline (String.concat "|" (List.map (pad_to 12) headers));
      print_endline (String.make (((List.length headers) * 13) - 1) '-');
      next_step [] versions versions

    | ShowStimulus, [host_t] ->
       Lwt_unix.run (host_t >>= show_stimulus prefs)

    | (ProbeAndPrint|CheckCerts|ExtractCerts|ScanSuites|ScanCompressions|ScanVersions|ShowStimulus), _ ->
      usage "probe_server" options (Some ("Some commands only work with a unique host."))


    | ProbeToDump, hosts_t ->
      let output_result = match !output_file with
        | "" -> (fun buf -> print_endline (hexdump (POutput.contents buf)))
        | "-" -> (fun buf -> print_endline (POutput.contents buf))
        | fn ->
          let f =
            try open_out_gen [Open_wronly; Open_creat; Open_excl] 0o644 fn
            with _ -> failwith ("Unable to create file: " ^ fn)
          in
          (fun buf -> POutput.output_buffer f buf; close_out f)
      in

      let lock_t, unlock_t =
        if !max_inflight_requests > 0
        then begin
          let sem = Lwt_semaphore.create !max_inflight_requests in
          let lock_t () = Lwt_semaphore.wait sem
          and unlock_t () = Lwt_semaphore.post sem; return () in
          (lock_t, unlock_t)
        end else (return, return)
      in

      let probe_one_host host_t =
        lock_t () >>= fun () ->
        host_t >>= fun ((ip_opt, hostname, port) as server_params) ->
        (* Handle SSLv2 answers? *)
        probe_server prefs server_params >>= fun (_, msgs, remaining_stuff, _) ->
        let content_to_dump = POutput.create () in
        let ip_str = match ip_opt with
	  | Some ip -> Unix.string_of_inet_addr ip
	  | None -> "0.0.0.0"
	and name_str = pop_opt "" (get_sni_name ip_opt hostname) in
        List.iter (dump_tls_record content_to_dump) (List.rev msgs);
        POutput.add_string content_to_dump remaining_stuff;
        let open AnswerDump in
        unlock_t () >>= fun () ->
        return {
          ip_type = 4;
          ip_addr = AD_IPv4 (PTypes.ipv4_of_string ip_str);
          port = port;
          name = name_str;
          campaign = !campaign_number;
          msg_type = 0;
          timestamp = Int64.of_float (Unix.time ());
          content = POutput.contents content_to_dump;
        }
      in
      let tmp_answer_dumps = Lwt_unix.run (Lwt_list.map_p probe_one_host hosts_t) in
      let answer_dumps =
	if !keep_empty_answers
	then tmp_answer_dumps
	else List.filter (fun a -> a.AnswerDump.content <> "") tmp_answer_dumps
      in
      let final_output = POutput.create () in
      List.iter (AnswerDump.dump_answer_dump_v2 final_output) answer_dumps;
      output_result final_output

  with
  | End_of_file -> ()
  | ParsingException (e, h) -> prerr_endline (string_of_exception e h); exit 1
  | Failure msg -> prerr_endline msg
  | e -> prerr_endline (Printexc.to_string e)
