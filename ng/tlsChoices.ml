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
  | Certificate of certificates
  | ServerHelloDone of server_hello_done
  | Unparsed_HSContent of string

let parse_handshake_content ?context:(ctx=None) handshake_type input =
  if !enrich_handshake_messages then begin
    match handshake_type with
      | HT_HelloRequest -> HelloRequest (parse_hello_request ~context:ctx input)
      | HT_ClientHello -> ClientHello (parse_client_hello ~context:ctx input)
      | HT_ServerHello -> ServerHello (parse_server_hello ~context:ctx input)
      | HT_NewSessionTicket -> NewSessionTicket (parse_new_session_ticket ~context:ctx input)
      | HT_Certificate -> Certificate (parse_certificates ~context:ctx input)
      | HT_ServerHelloDone -> ServerHelloDone (parse_server_hello_done ~context:ctx input)
      | _ -> Unparsed_HSContent (parse_rem_string input)
  end else Unparsed_HSContent (parse_rem_string input)

let dump_handshake_content = function
  | HelloRequest hr -> dump_hello_request hr
  | ClientHello ch -> dump_client_hello ch
  | ServerHello sh -> dump_server_hello sh
  | NewSessionTicket nst -> dump_new_session_ticket nst
  | Certificate certs -> dump_certificates certs
  | ServerHelloDone shd -> dump_server_hello_done shd
  | Unparsed_HSContent s -> s

let print_handshake_content indent name = function
  | HelloRequest hr -> print_hello_request indent name hr
  | ClientHello ch -> print_client_hello indent name ch
  | ServerHello sh -> print_server_hello indent name sh
  | NewSessionTicket nst -> print_new_session_ticket indent name nst
  | Certificate certs -> print_certificates indent name certs
  | ServerHelloDone shd -> print_server_hello_done indent name shd
  | Unparsed_HSContent s -> print_binstring indent name s
