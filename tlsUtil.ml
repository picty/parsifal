open Parsifal
open Asn1Engine
open Tls

let merge_records ?context:(ctx=None) ?enrich:(enrich=true) recs =
  let mk_merged_record ct v contents =
    let merged_contents = String.concat "" (List.rev contents) in
    let real_content =
      try
	let input = input_of_string "Merged records" merged_contents in
	parse_record_content ctx ~enrich:enrich ct input
      with ParsingException _ | Asn1Exception _ -> Unparsed_Record merged_contents
    in
    { content_type = ct;
      record_version = v;
      record_content = real_content; }
  in

  let rec merge_aux current_ct current_v current_content = function
    | [] -> [mk_merged_record current_ct current_v current_content]
    | record::r as l ->
      if current_ct = record.content_type &&
	current_v = record.record_version
      then begin
	let tmp_content = ((dump_record_content record.record_content)::current_content) in
	merge_aux current_ct current_v tmp_content r
      end else (mk_merged_record current_ct current_v current_content)::(handle_first l)

  and handle_first = function
    | [] -> []
    | record::r ->
      merge_aux record.content_type record.record_version [dump_record_content record.record_content] r

  in handle_first recs


let split_record record size =
  let ct = record.content_type
  and v = record.record_version
  and content = dump_record_content record.record_content in
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

