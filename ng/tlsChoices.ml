open ParsingEngine
open PrintingEngine
open TlsEnums
open TlsHandshake

let enrich_handshake_messages = ref true

type handshake_content =
  | ClientHello of client_hello
  | ServerHello of server_hello
  | Unparsed_HSContent of string

let parse_handshake_content handshake_type input =
  if !enrich_handshake_messages then begin
    match handshake_type with
      | HT_ClientHello -> ClientHello (parse_client_hello input)
      | HT_ServerHello -> ServerHello (parse_server_hello input)
      | _ -> Unparsed_HSContent (parse_rem_string input)
  end else Unparsed_HSContent (parse_rem_string input)

let dump_handshake_content = function
  | ClientHello ch -> dump_client_hello ch
  | ServerHello sh -> dump_server_hello sh
  | Unparsed_HSContent s -> s

let print_handshake_content indent name = function
  | ClientHello ch -> print_client_hello indent name ch
  | ServerHello sh -> print_server_hello indent name sh
  | Unparsed_HSContent s -> print_binstring indent name s
