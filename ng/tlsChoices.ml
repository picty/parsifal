open ParsingEngine
open DumpingEngine
open PrintingEngine
open TlsEnums
open TlsHandshake

let enrich_handshake_messages = ref true

type handshake_content =
  | ClientHello of client_hello
  | ServerHello of server_hello
  | Certificate of string list
  | ServerHelloDone
  | Unparsed_HSContent of string

(* TODO: ServerHelloDone should be coded as the hello_request in tlsHandshake.binrecs *)

let parse_certificate = parse_varlen_string "Certificate" parse_uint24

let parse_handshake_content handshake_type input =
  if !enrich_handshake_messages then begin
    match handshake_type with
      | HT_ClientHello -> ClientHello (parse_client_hello input)
      | HT_ServerHello -> ServerHello (parse_server_hello input)
      | HT_Certificate -> Certificate (parse_varlen_list "Certificates" parse_uint24 parse_certificate input)
      | HT_ServerHelloDone -> check_empty_input false input; ServerHelloDone
      | _ -> Unparsed_HSContent (parse_rem_string input)
  end else Unparsed_HSContent (parse_rem_string input)

let dump_handshake_content = function
  | ClientHello ch -> dump_client_hello ch
  | ServerHello sh -> dump_server_hello sh
  | Certificate cert_list -> dump_varlen_list dump_uint24 (dump_varlen_string dump_uint24) cert_list
  | ServerHelloDone -> ""
  | Unparsed_HSContent s -> s

let print_handshake_content indent name = function
  | ClientHello ch -> print_client_hello indent name ch
  | ServerHello sh -> print_server_hello indent name sh
  | Certificate cert_list -> print_list (print_binstring) indent "Certificates" cert_list
  | ServerHelloDone -> ""
  | Unparsed_HSContent s -> print_binstring indent name s
