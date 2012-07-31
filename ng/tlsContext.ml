open TlsEnums

type direction = ClientToServer | ServerToClient

type crypto_context = {
  mutable versions_proposed : tls_version * tls_version;
  mutable ciphersuites_proposed : ciphersuite list;
  mutable compressions_proposed : compression_method list;

  mutable s_version : tls_version;
  mutable s_ciphersuite : ciphersuite;
  mutable s_compression_method : compression_method;

  mutable s_client_random : string;
  mutable s_server_random : string;
  mutable s_session_id : string;
}

type tls_context = {
  mutable present : crypto_context;
  mutable future : crypto_context;
}

let empty_crypto_context () = {
  versions_proposed = V_Unknown 0xffff, V_Unknown 0;
  ciphersuites_proposed = [];
  compressions_proposed = [];

  s_version = V_Unknown 0;
  s_ciphersuite = TLS_NULL_WITH_NULL_NULL;
  s_compression_method = CM_Null;

  s_client_random = "";
  s_server_random = "";
  s_session_id = "";
}

let empty_context () = {
  present = empty_crypto_context ();
  future = empty_crypto_context ();
}

let check_record_version ctx record_version =
  ctx.present.s_version = (V_Unknown 0) ||
  ctx.present.s_version = record_version


type key_exchange_algorithm =
  | KX_RSA
  | KX_DHE
  | KX_Unknown

let extract_future_kx ctx = match ctx.future.s_ciphersuite with
  | TLS_DHE_RSA_WITH_AES_128_CBC_SHA
  | TLS_DHE_RSA_WITH_AES_256_CBC_SHA -> KX_DHE
  | _ -> KX_Unknown

