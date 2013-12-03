open Parsifal
open Tls


let clean_records ctx ?verbose:(verbose=false) ?enrich:(enrich=AlwaysEnrich) recs =
  let rec produce_clean_content accu ct input =
    if eos input
    then List.rev accu
    else begin
      let next_record_content =
	match try_parse ~report:true (parse_record_content ctx ct) input with
	| None -> Unparsed_Record (BasePTypes.parse_rem_binstring input)
	| Some res ->
	  begin
	    (* TODO: Write this somewhere else? *)
	    match ctx, res with
	    | Some c, Handshake {handshake_content = ServerHello sh} ->
	      c.future.proposed_ciphersuites <- [sh.ciphersuite]
            | Some c, Handshake {handshake_content = ServerKeyExchange ske} ->
	      c.future.s_server_key_exchange <- ske
	    | _ -> ()
	  end;
	  res
      in
      produce_clean_content (next_record_content::accu) ct input
    end
  in

  let produce_split_records ct v content =
    let merged_contents = POutput.contents content in
    let input = input_of_string ~verbose:verbose ~enrich:enrich "Merged records" merged_contents in
    let real_contents = produce_clean_content [] ct input in
    List.map (fun content -> {content_type = ct; record_version = v; record_content = content}) real_contents
  in

  let rec merge_aux ct v content = function
    | [] -> [produce_split_records ct v content]
    | record::r as l ->
      if ct = record.content_type &&
	v = record.record_version
      then begin
	dump_record_content content record.record_content;
	merge_aux ct v content r
      end else (produce_split_records ct v content)::(handle_first l)

  and handle_first = function
    | [] -> []
    | record::r ->
      let content = POutput.create () in
      dump_record_content content record.record_content;
      let clean_records = merge_aux record.content_type record.record_version content r in
      clean_records

  in List.flatten (handle_first recs)


let parse_all_records verbose input =
  let rec read_records accu i =
    if not (eos i)
    then begin
      match try_parse ~report:true (parse_tls_record None) i with
      | Some next -> read_records (next::accu) i
      | None -> List.rev accu, true
    end else List.rev accu, false
  in
  let tmp_input = { input with enrich = NeverEnrich } in
  let raw_recs, err = read_records [] tmp_input in
  input.cur_offset <- tmp_input.cur_offset;
  input.cur_bitstate <- tmp_input.cur_bitstate;
  if input.enrich = NeverEnrich
  then raw_recs, None, err
  else begin
    let ctx = Some (empty_context ()) in
    clean_records ctx ~verbose:verbose ~enrich:(input.enrich) raw_recs, ctx, err
  end
