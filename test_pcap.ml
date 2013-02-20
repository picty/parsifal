open Lwt
open Parsifal
open PTypes
open Pcap
open Getopt

let options = [
  mkopt (Some 'h') "help" Usage "show this help";
]

let getopt_params = {
  default_progname = "test_pcap";
  options = options;
  postprocess_funs = [];
}


let input_of_filename filename =
  Lwt_unix.openfile filename [Unix.O_RDONLY] 0 >>= fun fd ->
  input_of_fd filename fd

let rec handle_one_file input =
  lwt_try_parse lwt_parse_pcap_file input >>= function
    | None -> return ()
    | Some pcap ->
      print_string (print_pcap_file pcap);
      return ()


let _ =
  try
    let args = parse_args getopt_params Sys.argv in
    let open_files = function
      | [] -> input_of_channel "(stdin)" Lwt_io.stdin >>= fun x -> return [x]
      | _ -> Lwt_list.map_s input_of_filename args
    in
    Lwt_unix.run (open_files args >>= Lwt_list.iter_s handle_one_file);
  with
    | End_of_file -> ()
    | e -> print_endline (Printexc.to_string e)

