open Lwt
open ParsingEngine
open LwtParsingEngine
open PrintingEngine
open AnswerDump
open Tls
open TlsEnums
open Getopt

type action = IP | All | Suite | SKE
let action = ref IP
let raw_records = ref false

let options = [
  mkopt (Some 'h') "help" Usage "show this help";

  mkopt None "raw-records" (Set raw_records) "show raw records (do not try to reassemble them)";

  mkopt (Some 'a') "all" (TrivialFun (fun () -> action := All)) "show all the information and records of an answer";
  mkopt (Some 'I') "ip" (TrivialFun (fun () -> action := IP)) "only show the IP of the answers";
  mkopt (Some 's') "ciphersuite" (TrivialFun (fun () -> action := Suite)) "only show the ciphersuite chosen";
  mkopt (Some 'S') "ske" (TrivialFun (fun () -> action := SKE)) "only show information relative to ServerKeyExchange";
]

let getopt_params = {
  default_progname = "test_answerDump";
  options = options;
  postprocess_funs = [];
}


let input_of_filename filename =
  Lwt_unix.openfile filename [Unix.O_RDONLY] 0 >>= fun fd ->
  return (input_of_fd filename fd)

let parse_all_records answer =
  let rec read_records accu i =
    if not (eos i)
    then begin
      let next = (parse_tls_record i) in
      read_records (next::accu) i
    end else List.rev accu
  in
  (* TODO: Move this function in TlsUtil? *)
  let rec split_records accu ctx str_input recs = match str_input, recs with
    | None, [] -> List.rev accu, ctx, false
    | None, record::r ->
      let record_input = input_of_string (string_of_ipv4 answer.ip) (dump_record_content record.record_content) in
      let cursor = record.content_type, record.record_version, record_input in
      split_records accu ctx (Some cursor) r
    | Some (ct, v, i), _ ->
      if eos i then split_records accu ctx None recs
      else begin
	try
	  let next_content = parse_record_content ~context:(ctx) ~enrich:true ct i in
	  let next_record = {
	    content_type = ct;
	    record_version = v;
	    record_content = next_content;
	  } in
	  begin
	    match ctx, next_content with
	      | None, Handshake {handshake_content = ServerHello sh} ->
		let real_ctx = TlsContext.empty_context () in
		TlsEngine.update_with_server_hello real_ctx sh;
		split_records (next_record::accu) (Some real_ctx) str_input recs
	      | _ -> split_records (next_record::accu) ctx str_input recs
	  end;
	  
	with _ -> List.rev accu, ctx, true
      end
  in

  let answer_input = input_of_string (string_of_ipv4 answer.ip) answer.content in
  enrich_record_content := false;
  try
    if !raw_records
    then read_records [] answer_input, None, false
    else split_records [] None None (TlsUtil.merge_records ~enrich:false (read_records [] answer_input))
  with _ -> [], None, true
  



let rec handle_one_file input =
  lwt_parse_answer_dump input >>= fun answer ->
  let ip = string_of_ipv4 answer.ip in
  begin
    match !action with
      | IP -> print_endline ip; return ()
      | All ->
	let records, _, error = parse_all_records answer in
	print_endline ip;
	List.iter (fun r -> print_endline (print_tls_record "  " "TLS Record" r)) records;
	if error then print_endline "  ERROR";
	return ()
      | Suite ->
	let _, ctx, _ = parse_all_records answer in
	let cs = match ctx with
	  | None -> "ERROR"
	  | Some ctx -> string_of_ciphersuite ctx.TlsContext.future.TlsContext.s_ciphersuite.TlsContext.suite_name
	in
	Printf.printf "%s: %s\n" ip cs;
	return ()
      | SKE -> fail (Common.NotImplemented "SKE")
  end >>= fun () ->
  handle_one_file input

let _ =
  try
    let args = parse_args getopt_params Sys.argv in
    let open_files = function
      | [] -> return [input_of_channel "(stdin)" Lwt_io.stdin]
      | _ -> Lwt_list.map_s input_of_filename args
    in
    Lwt_unix.run (open_files args >>= Lwt_list.iter_s handle_one_file);
  with
    | End_of_file -> ()
    | e -> print_endline (Printexc.to_string e)

