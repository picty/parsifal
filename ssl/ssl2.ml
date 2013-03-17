open Lwt
open Parsifal
open BasePTypes 

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

let dump_ssl2_cipher_spec = function
  | SSL2CipherSpec x -> dump_pure_ssl2_cipher_spec x
  | TLSCipherSpec x -> TlsEnums.dump_ciphersuite x
  | UnparsedSSL2CipherSpec s -> s


enum ssl2_certificate_type (8, UnknownVal UnknownSSL2CertficateType) =
  | 0x01 -> SSL2_CT_X509_CERTIFICATE

enum ssl2_authentifcation_type (8, UnknownVal UnknownSSL2AuthenticationType) =
  | 0x01 -> SSL2_AT_MD5_WITH_RSA_ENCRYPTION

enum ssl2_error (16, UnknownVal UnknownSSL2Error) =
  | 0x0001 -> SSL2_ERR_NO_CIPHER			
  | 0x0002 -> SSL2_ERR_NO_CERTIFICATE			
  | 0x0004 -> SSL2_ERR_BAD_CERTIFICATE			
  | 0x0006 -> SSL2_ERR_UNSUPPORTED_CERTIFICATE_TYPE	


enum ssl2_handshake_type (8, UnknownVal UnknownSSL2HandshakeType) =
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

struct ssl2_server_hello = {
  ssl2_session_id_hit : uint8;
  ssl2_server_certificate_type : ssl2_certificate_type;
  ssl2_server_version : TlsEnums.tls_version;
  ssl2_server_certificate_length : uint16;
  ssl2_server_cipher_specs_length : uint16;
  ssl2_server_session_id_length : uint16;
  ssl2_server_certificate : container(ssl2_server_certificate_length) of Tls._certificate(());
  ssl2_server_cipher_specs : container(ssl2_server_cipher_specs_length) of list of ssl2_cipher_spec;
  ssl2_server_session_id : binstring(ssl2_server_session_id_length)
}

struct ssl2_request_certificate = {
  ssl2_authentifcation_type : ssl2_authentifcation_type;
  ssl2_certificate_challenge : binstring
}

struct ssl2_client_certificate = {
  ssl2_client_certificate_type : ssl2_certificate_type;
  ssl2_client_certificate_length : uint16;
  ssl2_response_length : uint16;
  ssl2_client_certificate : container(ssl2_client_certificate_length) of Tls._certificate (());
  ssl2_response : binstring(ssl2_response_length) (* TODO *)
}


union ssl2_handshake_content [enrich] (UnparsedSSL2HandshakeContent) =
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


type ssl2_record = {
  ssl2_long_header : bool;
  ssl2_is_escape : bool;
  ssl2_padding_length : int;
  ssl2_total_length : int;
  ssl2_content : ssl2_content
}



let parse_ssl2_record context input =
  let name = "SSLv2 record content"
  and parse_fun = parse_ssl2_content context
  and x = parse_uint16 input in
  if (x land 0x8000) = 0x8000 then
    let len = (x land 0x7fff) in
    { ssl2_long_header = false;
      ssl2_is_escape = false;
      ssl2_padding_length = 0;
      ssl2_total_length = len;
      ssl2_content = parse_container name len parse_fun input }
  else begin
    let len = x land 0x3fff in
    let pad_len = parse_uint8 input in
    let real_len = if context.cleartext then (len - pad_len) else len
    and real_pad_len = if context.cleartext then pad_len else 0 in
    let msg = parse_container name real_len parse_fun input in
    drop_bytes real_pad_len input;
    { ssl2_long_header = true;
      ssl2_is_escape = (x land 0x4000) = 0x4000;
      ssl2_padding_length = pad_len;
      ssl2_total_length = len;
      ssl2_content = msg }
  end

let lwt_parse_ssl2_record context input =
  let name = "SSLv2 record content"
  and parse_fun = parse_ssl2_content context in
  lwt_parse_uint16 input >>= fun x ->
  if (x land 0x8000) = 0x8000 then begin
    let len = x land 0x7fff in
    lwt_parse_container name len parse_fun input >>= fun content ->
    return { ssl2_long_header = false;
	     ssl2_is_escape = false;
	     ssl2_padding_length = 0;
	     ssl2_total_length = len;
	     ssl2_content = content }
  end else begin
    let len = x land 0x3fff in
    lwt_parse_uint8 input >>= fun pad_len ->
    let real_len = if context.cleartext then (len - pad_len) else len
    and real_pad_len = if context.cleartext then pad_len else 0 in
    lwt_parse_container name real_len parse_fun input >>= fun content ->
    lwt_drop_bytes real_pad_len input >>= fun _ ->
    return { ssl2_long_header = true;
      ssl2_is_escape = (x land 0x4000) = 0x4000;
      ssl2_padding_length = pad_len;
      ssl2_total_length = len;
      ssl2_content = content }
  end

let dump_ssl2_record record =
  let hdr =
    if record.ssl2_long_header
    then dump_uint16 (0x8000 lor (record.ssl2_total_length))
    else begin
      (dump_uint16 (if record.ssl2_is_escape then 0x4000 lor record.ssl2_total_length else record.ssl2_total_length)) ^
	(dump_uint8 record.ssl2_padding_length)
    end
  in
  let padding = String.make record.ssl2_padding_length '\x00' in
  hdr ^ (dump_ssl2_content record.ssl2_content) ^ padding

let value_of_ssl2_record record =
  VRecord [
    "@name", VString ("ssl2_record", false);
    "long_header", VBool record.ssl2_long_header;
    "is_escape", VBool record.ssl2_is_escape;
    "padding_len", VSimpleInt record.ssl2_padding_length;
    "total_len", VSimpleInt record.ssl2_total_length;
    "record_content", VLazy (lazy (value_of_ssl2_content record.ssl2_content))
  ]
