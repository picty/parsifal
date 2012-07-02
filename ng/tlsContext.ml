open TlsEnums

type direction = ClientToServer | ServerToClient

type crypto_context = {
  mutable ciphersuite : TlsEnums.ciphersuite
}

type tls_context = {
  mutable present : crypto_context;
  mutable future : crypto_context;
}

type key_exchange_algorithm =
  | KX_RSA
  | KX_DHE
  | KX_Unknown

let extract_future_kx ctx = match ctx.future.ciphersuite with
  | TLS_DHE_RSA_WITH_AES_128_CBC_SHA -> KX_DHE
  | _ -> KX_Unknown

let empty_context () = {
  present = {ciphersuite = TLS_NULL_WITH_NULL_NULL};
  future = {ciphersuite = TLS_NULL_WITH_NULL_NULL};
}
