open Parsifal
open BasePTypes
open PTypes
open X509
open Getopt


let parser_type = ref ""
type container = NoContainer | HexContainer | Base64Container
let container = ref NoContainer

let verbose = ref false
let enrich_style = ref DefaultEnrich
let set_enrich_level l =
  if l > 0 then begin
    enrich_style := EnrichLevel l;
    ActionDone
  end else ShowUsage (Some "enrich level should be a positive number.")
let update_enrich_level l =
  let new_style = match !enrich_style with
    | DefaultEnrich | NeverEnrich -> EnrichLevel l
    | EnrichLevel x -> EnrichLevel (max x l)
    | AlwaysEnrich -> AlwaysEnrich
  in enrich_style := new_style

type action = All | Get | JSon
let action = ref All
let path = ref ""

let type_list = ref false
let input_in_args = ref false


let options = [
  mkopt (Some 'h') "help" Usage "show this help";
  mkopt (Some 'v') "verbose" (Set verbose) "print more info to stderr";

  mkopt (Some 'T') "type" (StringVal parser_type) "select the parser type";
  mkopt (Some 'L') "list-types" (Set type_list) "prints the list of supported types";

  mkopt (Some 'i') "input-args" (Set input_in_args) "consider args as data, not filenames";

  mkopt (Some 'a') "all" (TrivialFun (fun () -> action := All)) "show all the information";
  mkopt (Some 'g') "get" (StringFun (fun s -> action := Get; path := s; ActionDone)) "select the info to extract";
  mkopt (Some 'j') "json" (TrivialFun (fun () -> action := JSon)) "represents the parsed value as a JSON";

  mkopt (Some 'B') "base64" (TrivialFun (fun () -> container := Base64Container)) "the data is first decoded as base64";
  mkopt (Some 'H') "hex" (TrivialFun (fun () -> container := HexContainer)) "the data is first decoded as hexa";

  mkopt None "always-enrich" (TrivialFun (fun () -> enrich_style := AlwaysEnrich)) "always enrich the structure parsed";
  mkopt None "never-enrich" (TrivialFun (fun () -> enrich_style := NeverEnrich)) "never enrich the structure parsed";
  mkopt None "enrich-level" (IntFun set_enrich_level) "enrich the structure parsed up to a certain level";
]



let type_handlers : (string, string_input -> value) Hashtbl.t = Hashtbl.create 10

let _ =
  Hashtbl.add type_handlers "string" (fun i -> value_of_string (parse_rem_string i));
  Hashtbl.add type_handlers "binstring" (fun i -> value_of_binstring (parse_rem_string i));
  Hashtbl.add type_handlers "x509" (fun i -> value_of_certificate (parse_certificate i));
  ()



let show_type_list error =
  print_endline "The types available are:";
  Hashtbl.iter (fun t -> fun _ -> print_string "  "; print_endline t) type_handlers;
  usage "perceval" options error


let parse_value input =
  try
    let raw_parse_fun = Hashtbl.find type_handlers !parser_type in
    let parse_fun = match !container with
      | NoContainer -> raw_parse_fun
      | HexContainer -> parse_hex_container raw_parse_fun
      | Base64Container -> Base64.parse_base64_container Base64.AnyHeader raw_parse_fun
    in
    let v = parse_fun input in
    match !action with
    | All -> print_endline (print_value ~verbose:!verbose v)
    | JSon -> print_endline (Json.json_of_value ~verbose:!verbose v)
    | Get ->
      match get v !path with
      | Left err -> if !verbose then prerr_endline err
      | Right s -> print_endline s
  with
    Not_found -> show_type_list (Some "parser type not found.")


let handle_stdin () = failwith "Not implemented"
let handle_filename filename = string_input_of_filename filename
let handle_inline data = input_of_string "(inline)" data


let _ =
  try
    let args = parse_args ~progname:"perceval" options Sys.argv in
    if !type_list then show_type_list None;  
    begin
      match args with
      | [] -> handle_stdin ()
      | l ->
	let f =
	  if !input_in_args
	  then handle_inline
	  else handle_filename
	in
	let handle_one_input s =
	  let input = f s in
	  parse_value input
	in
	List.iter handle_one_input l
    end;
    exit 0
  with
    | ParsingException (e, h) -> prerr_endline (string_of_exception e h); exit 1
    | e -> prerr_endline (Printexc.to_string e); exit 1
