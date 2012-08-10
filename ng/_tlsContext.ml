(* TLS_CONTEXT Code copied from _tlsContext.ml *)

open TlsEnums

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

  mutable s_server_key_exchange : server_key_exchange;

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

  s_server_key_exchange = Unparsed_SKEContent "";

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
