open Parsifal
open BasePTypes
open PTypes


let parse_string_until c input =
  if input.cur_offset < input.cur_length then begin
    let offset = input.cur_base + input.cur_offset in
    try
      let index = String.index_from input.str offset c in
      let res = parse_string (index - offset) input in
      ignore (parse_byte input);
      ignore (try_parse ~report:false (parse_magic "\n") input);
      res
    with Not_found -> parse_rem_string input
  end else raise (ParsingException (OutOfBounds, _h_of_si input))



type query_info = {
  query_method : string;
  query_path : string;
  query_version : string option;
}

type response_info = {
  response_version : string;
  response_code : string;
  response_status : string option;
}

type http_info =
| Query of query_info
| Response of response_info
| FirstLine of string

let mkopt = function
  | None -> VOption None
  | Some s -> VOption (Some (VString (s, false)))

let value_of_http_info = function
  | Query q ->
    VAlias ("Query", VRecord [
      "method", VString (q.query_method, false);
      "path", VString (q.query_path, false);
      "version", mkopt q.query_version;
    ])
  | Response r ->
    VAlias ("Response", VRecord [
      "version", VString (r.response_version, false);
      "code", VString (r.response_code, false);
      "status", mkopt r.response_status;
    ])
  | FirstLine l -> VString (l, false)



type http_message = {
  overall_length : int;
  http_info : http_info;
  headers : (string * string) list;
  body : string;
}


let split_header h input =
  try
    let i = String.index h ':' in
    let name = String.sub h 0 i in
    let l = String.length h in
    let start_of_hval = if l > (i+1) && h.[i+1] = ' ' then i+2 else i+1 in
    let v = String.sub h start_of_hval (l-start_of_hval) in
    name, v
  with Not_found ->
    emit_parsing_exception false (CustomException "Missing ':' in HTTP header") input;
    h, ""

let parse_http_message dir input =
  let rec parse_headers last_line hdrs input =
    if eos input then List.rev hdrs else begin
      let line = parse_string_until '\r' input in
      match last_line, line with
      | None, "" -> List.rev hdrs
      | Some h, "" -> List.rev ((split_header h input)::hdrs)
      | None, _ ->
	if line.[0] = ' '
	then begin
	  emit_parsing_exception true (CustomException "Invalid HTTP header starting with a space") input;
	  []
	end else parse_headers (Some line) hdrs input
      | Some h, _ ->
	if line.[0] = ' '
	then begin
	  let new_line = String.sub line 1 ((String.length line) - 1) in
	  parse_headers (Some (h ^ new_line)) hdrs input
	end else parse_headers (Some line) ((split_header h input)::hdrs) input
    end
  in
  let overall_length = input.cur_length in
  let first_line = parse_string_until '\r' input in
  ignore (try_parse ~report:false (parse_magic "\n") input);
  let http_info = match dir, string_split ' ' first_line with
    | Some ClientToServer, [m; p; v] -> Query {query_method = m; query_path = p; query_version = Some v}
    | Some ClientToServer, [m; p] -> Query {query_method = m; query_path = p; query_version = None}
    | Some ServerToClient, [v; c; s] -> Response {response_version = v; response_code = c; response_status = Some s}
    | Some ServerToClient, [v; c] -> Response {response_version = v; response_code = c; response_status = None}
    | _ -> FirstLine first_line
  in
  let headers = parse_headers None [] input in
  let body = parse_rem_string input in
  { overall_length = overall_length;
    http_info = http_info;
    headers = headers;
    body = body }


let dump_http_messge _buf _msg = not_implemented "dump_http_messge"


let value_of_headers hdrs =
  let htab = Hashtbl.create 10 in
  let add_hdr (name, v_str) =
    let v = VString (v_str, false) in
    let v_to_insert =
      try
        match Hashtbl.find htab name with
        | VList l -> VList (l@[v])
        | v_old -> VList [v_old; v]
      with Not_found -> v
    in
    Hashtbl.replace htab name v_to_insert
  in
  List.iter add_hdr hdrs;
  let mk_record n v l = (n, v)::l in
  VRecord (Hashtbl.fold mk_record htab [])

let value_of_http_message msg = VRecord [
  "@name", VString ("http_message", false);
  "overall_length", VSimpleInt msg.overall_length;
  "http_info", value_of_http_info msg.http_info;
  "headers", value_of_headers msg.headers;
  "body", VString (msg.body, false);
]
