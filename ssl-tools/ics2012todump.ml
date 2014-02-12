open Parsifal
open BasePTypes
open PTypes
open AnswerDump
open Getopt


type 'a quoted_printable_container = 'a

let parse_quoted_printable_container parse_fun input =
  let buf = Buffer.create 1024 in
  while not (eos input) do
    let c = parse_byte input in
    if c = int_of_char '='
    then begin
      let hibits = extract_4bits input in
      let lobits = extract_4bits input in
      Buffer.add_char buf (char_of_int ((hibits lsl 4) lor lobits))
    end else Buffer.add_char buf (char_of_int c)
  done;
  let content = Buffer.contents buf in
  let new_input = get_in_container input "quoted_printable_container" content in
  let res = parse_fun new_input in
  check_empty_input true new_input;
  res

let dump_quoted_printable_container _dump_fun _buf _o =
  raise (ParsingException (NotImplemented "dump_quoted_printable", []))

let value_of_quoted_printable_container = value_of_container




let rec convert_lines input_f output_f =
  match string_split ' ' (input_line input_f) with
  | [ip_s; _timestamp; answer_q] ->
    let ip = match List.map (fun elt_s -> char_of_int (int_of_string elt_s)) (string_split '.' ip_s) with
      | [c1; c2; c3; c4] -> Printf.sprintf "%c%c%c%c" c1 c2 c3 c4
      | _ -> failwith (Printf.sprintf "Invalid IP address (%s)" ip_s)
    and content = parse_quoted_printable_container parse_rem_binstring (input_of_string "quoted_string" answer_q) in 
    let answer = {
      ad_ip = ip;
      ad_port = 443;
      ad_name = "";
      ad_client_hello_type = 42;
      ad_msg_type = 0;
      ad_content = content
    } in
    let answer_s = exact_dump_answer_dump answer in
    output_string output_f answer_s;
    convert_lines input_f output_f
  | ip_s::_ -> failwith (Printf.sprintf "Invalid line (%s)" ip_s)
  | [] -> convert_lines input_f output_f



let _ =
  convert_lines stdin stdout
