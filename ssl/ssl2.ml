open Lwt
open Parsifal
open BasePTypes 
open PTypes

type ssl2_context = {
  cleartext : bool
}


enum pure_ssl2_cipher_spec (24, UnknownVal UnknownSSL2CipherSpec) =
  | 0x010080 -> SSL2_CK_RC4_128_WITH_MD5
  | 0x020080 -> SSL2_CK_RC4_128_EXPORT40_WITH_MD5
  | 0x030080 -> SSL2_CK_RC2_128_CBC_WITH_MD5
  | 0x040080 -> SSL2_CK_RC2_128_CBC_EXPORT40_WITH_MD5
  | 0x050080 -> SSL2_CK_IDEA_128_CBC_WITH_MD5
  | 0x060040 -> SSL2_CK_DES_64_CBC_WITH_MD5
  | 0x0700C0 -> SSL2_CK_DES_192_EDE3_CBC_WITH_MD5	

union ssl2_cipher_spec [enrich; exhaustive] (UnparsedSSL2CipherSpec) =
  | true -> SSL2CipherSpec of pure_ssl2_cipher_spec
  | false -> TLSCipherSpec of TlsEnums.ciphersuite

(* The use of masking is ugly... *)
let parse_ssl2_cipher_spec input =
  let x = peek_uint8 input in
  if x = 0 then drop_bytes 1 input;
  parse_ssl2_cipher_spec (x <> 0) input

let dump_ssl2_cipher_spec buf = function
  | SSL2CipherSpec x -> dump_pure_ssl2_cipher_spec buf x
  | TLSCipherSpec x ->
    POutput.add_char buf '\x00';
    TlsEnums.dump_ciphersuite buf x
  | UnparsedSSL2CipherSpec s -> POutput.add_string buf s

let int_of_ssl2_cipher_spec = function
  | SSL2CipherSpec x -> int_of_pure_ssl2_cipher_spec x
  | TLSCipherSpec x -> TlsEnums.int_of_ciphersuite x
  | UnparsedSSL2CipherSpec _ -> failwith "Impossible"


(* TODO: Should it be SoftExceptions if they are ever implemented? *)
(* It would allow to forge invalid packets, at least... *)
enum ssl2_certificate_type (8, Exception) =
  | 0x01 -> SSL2_CT_X509_CERTIFICATE

enum ssl2_authentifcation_type (8, Exception) =
  | 0x01 -> SSL2_AT_MD5_WITH_RSA_ENCRYPTION

enum ssl2_error (16, Exception) =
  | 0x0001 -> SSL2_ERR_NO_CIPHER
  | 0x0002 -> SSL2_ERR_NO_CERTIFICATE
  | 0x0004 -> SSL2_ERR_BAD_CERTIFICATE
  | 0x0006 -> SSL2_ERR_UNSUPPORTED_CERTIFICATE_TYPE

enum ssl2_handshake_type (8, Exception) =
  | 0 -> SSL2_HT_ERROR
  | 1 -> SSL2_HT_CLIENT_HELLO
  | 2 -> SSL2_HT_CLIENT_MASTER_KEY
  | 3 -> SSL2_HT_CLIENT_FINISHED
  | 4 -> SSL2_HT_SERVER_HELLO
  | 5 -> SSL2_HT_SERVER_VERIFY
  | 6 -> SSL2_HT_SERVER_FINISHED
  | 7 -> SSL2_HT_REQUEST_CERTIFICATE
  | 8 -> SSL2_HT_CLIENT_CERTIFICATE

struct ssl2_client_hello = {
  ssl2_client_version : TlsEnums.tls_version;
  ssl2_client_cipher_specs_length : uint16;
  ssl2_client_session_id_length : uint16;
  ssl2_challenge_length : uint16;
  ssl2_client_cipher_specs : container(ssl2_client_cipher_specs_length) of list of ssl2_cipher_spec;
  ssl2_client_session_id : binstring(ssl2_client_session_id_length);
  ssl2_challenge : binstring(ssl2_challenge_length)
}

struct ssl2_client_master_key = {
  ssl2_cipher_spec : ssl2_cipher_spec;
  ssl2_clear_key_length : uint16;
  ssl2_encrypted_key_length : uint16;
  ssl2_key_arg_length : uint16;
  ssl2_clear_key : binstring(ssl2_clear_key_length);
  ssl2_encrypted_key : binstring(ssl2_encrypted_key_length);
  ssl2_key_arg : binstring(ssl2_key_arg_length)
}

let enrich_certificate_in_server_hello = ref false
struct ssl2_server_hello = {
  ssl2_session_id_hit : uint8;
  ssl2_server_certificate_type : ssl2_certificate_type;
  ssl2_server_version : TlsEnums.tls_version;
  ssl2_server_certificate_length : uint16;
  ssl2_server_cipher_specs_length : uint16;
  ssl2_server_session_id_length : uint16;
  ssl2_server_certificate : container(ssl2_server_certificate_length) of
      trivial_union(enrich_certificate_in_server_hello) of X509.certificate;
  ssl2_server_cipher_specs : container(ssl2_server_cipher_specs_length) of list of ssl2_cipher_spec;
  ssl2_server_session_id : binstring(ssl2_server_session_id_length)
}

struct ssl2_request_certificate = {
  ssl2_authentifcation_type : ssl2_authentifcation_type;
  ssl2_certificate_challenge : binstring
}

let enrich_certificate_in_client_certificate = ref false
struct ssl2_client_certificate = {
  ssl2_client_certificate_type : ssl2_certificate_type;
  ssl2_client_certificate_length : uint16;
  ssl2_response_length : uint16;
  ssl2_client_certificate : container(ssl2_client_certificate_length) of
      trivial_union(enrich_certificate_in_client_certificate) of X509.certificate;
  ssl2_response : binstring(ssl2_response_length) (* TODO *)
}


union ssl2_handshake_content [enrich; exhaustive] (UnparsedSSL2HandshakeContent) =
  | SSL2_HT_ERROR -> SSL2Error of ssl2_error
  | SSL2_HT_CLIENT_HELLO -> SSL2ClientHello of ssl2_client_hello
  | SSL2_HT_CLIENT_MASTER_KEY -> SSL2ClientMasterKey of ssl2_client_master_key
  | SSL2_HT_CLIENT_FINISHED -> SSL2ClientFinished of binstring
  | SSL2_HT_SERVER_HELLO -> SSL2ServerHello of ssl2_server_hello
  | SSL2_HT_SERVER_VERIFY -> SSL2ServerVerify of binstring
  | SSL2_HT_SERVER_FINISHED -> SSL2ServerFinished of binstring
  | SSL2_HT_REQUEST_CERTIFICATE -> SSL2RequestCertificate of ssl2_request_certificate
  | SSL2_HT_CLIENT_CERTIFICATE -> SSL2ClientCertificate of ssl2_client_certificate

struct ssl2_handshake = {
  ssl2_handshake_type : ssl2_handshake_type;
  ssl2_handshake_content : ssl2_handshake_content(ssl2_handshake_type)
}

union ssl2_content [enrich] (SSL2EncryptedMessage) =
  | { cleartext = true } -> SSL2Handshake of ssl2_handshake


struct ssl2_long_header = {
  ssl2_is_escape : bit_bool;
  ssl2_total_len : bit_int[14];
  ssl2_pad_len : uint8;
}

union ssl2_header [enrich; exhaustive] (UnparsedSSL2Header) =
  | true -> SSL2ShortHeader of bit_int[15]
  | false -> SSL2LongHeader of ssl2_long_header

let pad_len_of_hdr = function
  | SSL2LongHeader h -> h.ssl2_pad_len
  | _ -> 0

let msg_len_of_hdr = function
  | SSL2LongHeader h -> h.ssl2_total_len - h.ssl2_pad_len
  | SSL2ShortHeader l -> l
  | _ -> 0 (* TODO: Erreur *)

struct ssl2_record [param context] = {
  ssl2_short_header : bit_bool;
  ssl2_header : ssl2_header(ssl2_short_header);
  ssl2_content : container(msg_len_of_hdr ssl2_header) of ssl2_content(context);
  ssl2_padding : binstring(pad_len_of_hdr ssl2_header);
}
