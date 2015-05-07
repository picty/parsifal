open Lwt
open LwtUtil
open Parsifal
open BasePTypes
open PTypes
open AnswerDump
open Ssl2
open Tls
open TlsEnums
open TlsEngineNG
open X509


(* TODO: Check that parsing exceptions are correctly handled *)


(**************************************)
(* Helpers to manipulate answer dumps *)
(**************************************)


let process_helper verbose parse_fun handle_fun dump_fun =
  let rec handle_one_answer input =
    let finalize_ok answer =
      begin
	match handle_fun answer with
	| None -> ()
	| Some new_answer -> print_string (exact_dump dump_fun new_answer);
      end;
      handle_one_answer input
    and finalize_nok = function
      | (ParsingException _) as e ->
	if input.lwt_eof && (input.string_input.cur_length = 0)
        then return ()
	else fail e
      | e -> fail e
    in try_bind (fun () -> lwt_parse_wrapper parse_fun input) finalize_ok finalize_nok
  in
  let t =
    input_of_channel ~verbose:(verbose) "(stdin)" Lwt_io.stdin >>= fun (input : lwt_input) ->
    handle_one_answer input
  in Lwt_unix.run t




(*****************************************)
(* Helpers to parse answer dump contents *)
(*****************************************)


let parse_all_ssl2_records enrich_style verbose answer =
  let rec read_ssl2_records accu i =
    if not (eos i)
    then begin
      match try_parse (parse_ssl2_record { cleartext = true }) i with
      | Some next -> read_ssl2_records (next::accu) i
      | None -> List.rev accu, true
    end else List.rev accu, false
  in
  let answer_input = input_of_string ~enrich:(enrich_style) ~verbose:(verbose) (string_of_v2_ip answer.ip_addr) answer.content in
  enrich_record_content := false;
  let raw_recs, err = read_ssl2_records [] answer_input in
  raw_recs, None, err

let parse_all_tls_records enrich_style verbose answer =
  let prefs = {
    random_generator = RandomEngine.dummy_random_generator ();
    acceptable_versions = (V_Unknown 0, V_Unknown 0xffff);
    acceptable_ciphersuites = [];
    acceptable_compressions = [];
    use_extensions = false;
    available_certificates = [];
    directive_behaviour = false;
    send_SNI = false;
    server_names = [];
  } in
  let ctx = empty_context prefs in
  let answer_input = input_of_string ~verbose:(verbose) ~enrich:(enrich_style) (string_of_v2_ip answer.ip_addr) answer.content in
  let recs, remaining = parse_all_records ServerToClient (Some ctx) answer_input in
  recs, ctx, remaining

let parse_all_records enrich_style verbose answer =
  let tls_records =
    try let r, _, _ = parse_all_tls_records enrich_style verbose answer in r
    with Failure _ -> []
  in
  if tls_records <> []
  then Right tls_records
  else begin
    let ssl2_records, _, _ = parse_all_ssl2_records enrich_style verbose answer in
    Left ssl2_records
  end

let parse_records_as_values enrich_style verbose answer =
  (* TODO: We do not catch exceptions here... *)
  match parse_all_tls_records enrich_style verbose answer with
  | [], _, None -> [], false
  | [], _, Some _ ->
    let records, _, err = parse_all_ssl2_records enrich_style verbose answer in
    List.map value_of_ssl2_record records, err
  | records, _, x ->
    List.map value_of_tls_record records, x <> None


type parsed_answer_content =
  | Empty
  | Junk of string * binstring
  | SSLv2Handshake of tls_version * ssl2_cipher_spec list * certificate trivial_union
  | SSLv2Alert of ssl2_error
  | TLSHandshake of tls_version * tls_version * ciphersuite * (certificate trivial_union) list
  | TLSAlert of tls_version * tls_alert_level * tls_alert_type

type parsed_answer = {
  pa_ip : ipv4_or_6;
  pa_port : int;
  pa_name : string;
  pa_campaign : int;
  pa_timestamp : int64;
  pa_content : parsed_answer_content;
}


let parse_answer enrich_style verbose answer =
  let records = parse_all_records enrich_style verbose answer in
  let parsed_content = match records, answer.content with
    | _, "" -> Empty

    | Right [{ content_type = CT_Alert;
               record_version = v;
               record_content = Alert a }], _ ->
       TLSAlert (v, a.alert_level, a.alert_type)
    | Left [{ ssl2_content = SSL2Handshake {
                ssl2_handshake_type = SSL2_HT_ERROR;
                ssl2_handshake_content = SSL2Error e }}], _ ->
       SSLv2Alert e

    | Right ({ content_type = CT_Handshake;
               record_version = ext_v;
               record_content = Handshake {
                 handshake_type = HT_ServerHello;
                 handshake_content = ServerHello sh }}::
             { content_type = CT_Handshake;
               record_content = Handshake {
                 handshake_type = HT_Certificate;
                 handshake_content = Certificate certs }}::_), _ ->
       TLSHandshake (ext_v, sh.server_version, sh.ciphersuite, certs)
    | Left ({ ssl2_content = SSL2Handshake {
                ssl2_handshake_type = SSL2_HT_SERVER_HELLO;
                ssl2_handshake_content = SSL2ServerHello sh }}::_), _ ->
       SSLv2Handshake (sh.ssl2_server_version, sh.ssl2_server_cipher_specs, sh.ssl2_server_certificate)
    | Right ({ content_type = CT_Handshake;
               record_version = ext_v;
               record_content = Handshake {
                 handshake_type = HT_ServerHello;
                 handshake_content = ServerHello sh }}::_), _ ->
       (* TODO: Should this [] be a None to explicitly say "No Certificate message found"? *)
       TLSHandshake (ext_v, sh.server_version, sh.ciphersuite, [])

    | Right ({ content_type = CT_Handshake;
               record_content = Handshake {
                 handshake_type = HT_ClientHello;
                 handshake_content = ClientHello _ }}::_), s ->
       Junk ("ClientHello", s)
    | _, s ->
       let guess =
         if (String.length s >= 7) && (String.sub s 0 7 = "\x15\x03\x01\x00\x02\xff\xff")
         then "Alert-FF-FF"
         else if String.length s >= 5 then begin
           match (String.sub s 0 5) with
	   | "SSH-1" -> "SSH-1"
	   | "SSH-2" -> "SSH-2"
	   | "HTTP/"
	   | "<!DOC" -> "HTTP"
	   (* Handle SMTP? "220 main2 ESMTP." *)
	   | _ -> ""
         end else ""
       in Junk (guess, s)
  in {
    pa_ip = answer.ip_addr;
    pa_port = answer.port;
    pa_name = answer.name;
    pa_campaign = answer.campaign;
    pa_timestamp = answer.timestamp;
    pa_content = parsed_content
  }
