open Parsifal
open Libpgp

let _ =
    try
        let input_file = ref "" in
        let armored_msg = ref false in

        let args_spec = ( let open Getopt in [
            mkopt (Some 'h') "help" Usage "Show this help";
            mkopt (Some 'a') "armor" (Set armored_msg) "Specify that input is armored in ASCII-Radix64" ;
            mkopt (Some 'f') "file" (StringVal input_file) "Name of the file to analyze. If not specified, stdin is read." ;
        ]) in

        let _ = Getopt.parse_args ~progname:"openpgp" args_spec Sys.argv in

        let input = if !input_file <> "" then begin
                        string_input_of_filename !input_file
                    end else begin
                        string_input_of_stdin ()
                    end
        in

        let openpgp_output_options = { default_output_options with oo_verbose=true } in

        if !armored_msg then begin
            let msg = parse_armored_openpgp_message input in
            print_endline (Json.json_of_value ~options:openpgp_output_options (value_of_armored_openpgp_message msg))
        end else begin
            let msg = parse_openpgp_message input in
            print_endline (Json.json_of_value ~options:openpgp_output_options (value_of_openpgp_message msg))
        end
    with
    | ParsingException (e, h) -> prerr_endline (string_of_exception e h); exit 1
    | e -> prerr_endline (Printexc.to_string e); exit 1

