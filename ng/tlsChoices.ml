open ParsingEngine
open DumpingEngine
open PrintingEngine
open TlsEnums
open TlsHandshake

let enrich_handshake_messages = ref true

type handshake_content =
  | HelloRequest of hello_request
  | ClientHello of client_hello
  | ServerHello of server_hello
  | NewSessionTicket of new_session_ticket
  | Certificate of string list
  | ServerHelloDone of server_hello_done
  | Unparsed_HSContent of string

(* TODO: Certificate is different from the rest. This needs to be
   changed to allow this choice to be generated magically *)

let parse_certificate = parse_varlen_string "Certificate" parse_uint24

let parse_handshake_content handshake_type input =
  if !enrich_handshake_messages then begin
    match handshake_type with
      | HT_HelloRequest -> HelloRequest (parse_hello_request input)
      | HT_ClientHello -> ClientHello (parse_client_hello input)
      | HT_ServerHello -> ServerHello (parse_server_hello input)
      | HT_NewSessionTicket -> NewSessionTicket (parse_new_session_ticket input)
      | HT_Certificate -> Certificate (parse_varlen_list "Certificates" parse_uint24 parse_certificate input)
      | HT_ServerHelloDone -> ServerHelloDone (parse_server_hello_done input)
      | _ -> Unparsed_HSContent (parse_rem_string input)
  end else Unparsed_HSContent (parse_rem_string input)

let dump_handshake_content = function
  | HelloRequest hr -> dump_hello_request hr
  | ClientHello ch -> dump_client_hello ch
  | ServerHello sh -> dump_server_hello sh
  | NewSessionTicket nst -> dump_new_session_ticket nst
  | Certificate cert_list -> dump_varlen_list dump_uint24 (dump_varlen_string dump_uint24) cert_list
  | ServerHelloDone shd -> dump_server_hello_done shd
  | Unparsed_HSContent s -> s

let print_handshake_content indent name = function
  | HelloRequest hr -> print_hello_request indent name hr
  | ClientHello ch -> print_client_hello indent name ch
  | ServerHello sh -> print_server_hello indent name sh
  | NewSessionTicket nst -> print_new_session_ticket indent name nst
  | Certificate cert_list -> print_list (print_binstring) indent "Certificates" cert_list
  | ServerHelloDone shd -> print_server_hello_done indent name shd
  | Unparsed_HSContent s -> print_binstring indent name s
