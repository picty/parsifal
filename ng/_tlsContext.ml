(* TLS_CONTEXT Code copied from _tlsContext.ml *)

type direction = ClientToServer | ServerToClient

type key_exchange_algorithm =
  | KX_RSA
  | KX_DH
  | KX_DHE
  | KX_ECDH
  | KX_ECDHE
  | KX_Unknown

type authentication_algorithm =
  | AU_Null
  | AU_RSA
  | AU_DSS
  | AU_ECDSA
  | AU_Unknown

type encryption_blockcipher =
  | BC_DES
  | BC_RC2
  | BC_IDEA
  | BC_3DES
  | BC_ARIA
  | BC_SEED
  | BC_CAMELLIA
  | BC_AES

type encryption_streamcipher =
  | SC_RC4

type encryption_algorithm =
  | ENC_Null
  | ENC_CBC of encryption_blockcipher * int
  | ENC_GCM of encryption_blockcipher * int
  | ENC_Stream of encryption_streamcipher * int
  | ENC_Unknown

type hash_function =
  | HF_MD5
  | HF_SHA1
  | HF_SHA256
  | HF_SHA384

type integrity_algorithm =
  | MAC_HMAC of hash_function * int
  | MAC_AEAD
  | MAC_Unknown

type pseudo_random_function =
  | PRF_Default
  | PRF_SHA256
  | PRF_SHA384
  | PRF_Unknown


type ciphersuite_description = {
  suite_name : TlsEnums.ciphersuite;
  kx : key_exchange_algorithm;
  au : authentication_algorithm;
  enc : encryption_algorithm;
  mac : integrity_algorithm;
  prf : pseudo_random_function;
  export : bool;
  min_version : int;
  max_version : int;
}


let ciphersuite_descriptions = Hashtbl.create 300

let find_csdescr cs =
  try Hashtbl.find ciphersuite_descriptions cs
  with Not_found -> {
    suite_name = cs;
    kx = KX_Unknown; au = AU_Unknown;
    enc = ENC_Unknown; mac = MAC_Unknown;
    prf = PRF_Unknown;
    export = false; min_version = 0; max_version = 0xffff;
  }


type crypto_context = {
  mutable versions_proposed : TlsEnums.tls_version * TlsEnums.tls_version;
  mutable ciphersuites_proposed : TlsEnums.ciphersuite list;
  mutable compressions_proposed : TlsEnums.compression_method list;

  mutable s_version : TlsEnums.tls_version;
  mutable s_ciphersuite : ciphersuite_description;
  mutable s_compression_method : TlsEnums.compression_method;

  mutable s_client_random : string;
  mutable s_server_random : string;
  mutable s_session_id : string;
}

type tls_context = {
  mutable present : crypto_context;
  mutable future : crypto_context;
}

let empty_crypto_context () = {
  versions_proposed = TlsEnums.V_Unknown 0xffff, TlsEnums.V_Unknown 0;
  ciphersuites_proposed = [];
  compressions_proposed = [];

  s_version = TlsEnums.V_Unknown 0;
  s_ciphersuite = find_csdescr TlsEnums.TLS_NULL_WITH_NULL_NULL;
  s_compression_method = TlsEnums.CM_Null;

  s_client_random = "";
  s_server_random = "";
  s_session_id = "";
}

let empty_context () = {
  present = empty_crypto_context ();
  future = empty_crypto_context ();
}


let check_record_version ctx record_version =
  ctx.present.s_version = (TlsEnums.V_Unknown 0) ||
  ctx.present.s_version = record_version

(* TLS_CONTEXT End of the code copied *)
