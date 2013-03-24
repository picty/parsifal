open Lwt
open Parsifal
open Protobuf
open Getopt


type action = Examples | Print
let action = ref Print
let set_action value = TrivialFun (fun () -> action := value)

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

let options = [
  mkopt (Some 'h') "help" Usage "show this help";
  mkopt (Some 'v') "verbose" (Set verbose) "print more info to stderr";
  mkopt (Some 'e') "examples" (set_action Examples) "show examples";

  mkopt None "always-enrich" (TrivialFun (fun () -> enrich_style := AlwaysEnrich)) "always enrich the structure parsed";
  mkopt None "never-enrich" (TrivialFun (fun () -> enrich_style := NeverEnrich)) "never enrich the structure parsed";
  mkopt None "enrich-level" (IntFun set_enrich_level) "enrich the structure parsed up to a certain level";
]



let examples = [
  "\x08\x96\x01";
  "\x12\x07\x74\x65\x73\x74\x69\x6e\x67";
  "\x1a\x03\x08\x96\x01";
]

let test_one_buf b =
  print_endline (print_rec_protobuf (parse_rec_protobuf (input_of_string "Buf" b)))




let handle_one_file input =
  lwt_parse_rec_protobuf input >>= function protobuf ->
    print_endline (print_rec_protobuf protobuf);
    return ()

let _ =
  try
    let args = parse_args ~progname:"test_protobuf" options Sys.argv in
    match !action with
    | Examples -> List.iter test_one_buf examples
    | Print ->
      let open_files = function
        | [] -> input_of_channel ~enrich:(!enrich_style) ~verbose:(!verbose) "(stdin)" Lwt_io.stdin >>= fun x -> return [x]
        | _ -> Lwt_list.map_s input_of_filename args
      in
      Lwt_unix.run (open_files args >>= Lwt_list.iter_s handle_one_file);
  with
    | End_of_file -> ()
    | ParsingException (e, h) -> prerr_endline (string_of_exception e h)
    | e -> prerr_endline (Printexc.to_string e)
