open TlsEnums


(* Simple TLS records *)

struct tls_alert = {
  alert_level : tls_alert_level;
  alert_type : tls_alert_type
}

struct change_cipher_spec = {
  change_cipher_spec_value : change_cipher_spec_value
}



(* Handshake records and choices *)

(* Explicit ("name_type") *)
union sni_name (Unparsed_SNIName, [enrich]) =
  | NT_HostName -> HostName of string[uint16]

struct server_name = {
  sni_name_type : name_type;
  sni_name : sni_name(_sni_name_type)
}

union server_name_content (Unparsed_ServerNameContent, [enrich; exhaustive]) =
  | ClientToServer -> ClientServerName of (list[uint16] of server_name)
  | ServerToClient -> ServerServerName

union hello_extension_content (Unparsed_HelloExtension, [enrich; param direction]) =
  | HE_ServerName -> ServerName of server_name_content(direction)
  | HE_MaxFragmentLength -> MaxFragmentLength of uint8
  | HE_ClientCertificateURL -> ClientCertificateURL
  (* TODO | HE_TrustedCAKeys -> TrustedCAKeys of ? *)
  | HE_TruncatedMAC -> TruncatedMAC
  (* TODO | HE_StatusRequest -> StatusRequest of ? *)
  (* TODO | HE_UserMapping -> UserMapping of ? *)
  (* TODO | HE_ClientAuthz -> ClientAuthz of ? *)
  (* TODO | HE_ServerAuthz -> ServerAuthz of ? *)
  (* TODO | HE_CertType -> CertType of ? *)
  | HE_EllipticCurves -> EllipticCurves of (list[uint16] of ec_named_curve)
  | HE_ECPointFormats -> ECPointFormats of (list[uint8] of ec_point_format)
  (* TODO | HE_SRP -> SRPExtension of ? *)
  (* TODO | HE_SignatureAlgorithms -> SignatureAlgorithms of ? *)
  (* TODO | HE_UseSRTP -> UseSRTP of ? *)
  | HE_Heartbeat -> HeartbeatExtension of heartbeat_mode
  (* TODO | HE_SessionTicket -> SessionTicket of ? *)
  (* TODO | HE_RenegotiationInfo -> RenegotiationInfo of ? *)

struct hello_extension [param direction] = {
  extension_type : extension_type;
  extension_data : container[uint16] of hello_extension_content(direction; _extension_type)
}

struct client_hello = {
  client_version : tls_version;
  client_random : binstring(32);
  client_session_id : binstring[uint8];
  ciphersuites : list[uint16] of ciphersuite;
  compression_methods : list[uint8] of compression_method;
  optional client_extensions : list[uint16] of hello_extension(ClientToServer)
}

struct server_hello = {
  server_version : tls_version;
  server_random : binstring(32);
  server_session_id : binstring[uint8];
  ciphersuite : ciphersuite;
  compression_method : compression_method;
  optional server_extensions : list[uint16] of hello_extension(ServerToClient)
}

struct new_session_ticket = {
  ticket_lifetime_hint : uint32;
  ticket : binstring[uint16]
}

struct certificates = {
  (* TODO: change this since it should be either binstring either cert *)
  certificate_list : list[uint24] of binstring[uint24]
}

struct server_dh_params = {
  dh_p : binstring[uint16];
  dh_g : binstring[uint16];
  dh_Ys: binstring[uint16]
}

(* TODO: signature? *)
struct ske_dhe_params = {
  params : server_dh_params;
  signature : binstring
}


union server_key_exchange (Unparsed_SKEContent, [enrich]) =
  | KX_DHE -> SKE_DHE of ske_dhe_params



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



struct signature_and_hash_algorithm = {
  hash_algorithm : hash_algorithm;
  signature_algorithm : signature_algorithm
}

struct certificate_request = {
  certificate_types : client_certificate_type;
  supported_signature_algorithms : list[uint16] of signature_and_hash_algorithm;
  (* TODO: change this since it should be either binstring either dn *)
  certificate_authorities : list[uint16] of binstring[uint16]
}

union handshake_content (Unparsed_HSContent, [enrich; param context]) =
  | HT_HelloRequest -> HelloRequest
  | HT_ClientHello -> ClientHello of client_hello
  | HT_ServerHello -> ServerHello of server_hello
  | HT_NewSessionTicket -> NewSessionTicket of new_session_ticket
  | HT_Certificate -> Certificate of certificates
  | HT_ServerKeyExchange -> ServerKeyExchange of server_key_exchange(match context with None -> KX_Unknown | Some ctx -> ctx.future.s_ciphersuite.kx)
  | HT_CertificateRequest -> CertificateRequest of certificate_request
  | HT_ServerHelloDone -> ServerHelloDone

struct handshake_msg [param context] = {
  handshake_type : hs_message_type;
  handshake_content : container[uint24] of handshake_content(context; _handshake_type)
}

struct heartbeat_msg = {
  heartbeat_message_type : heartbeat_message_type;
  heartbeat_payload : binstring[uint16];
  heartbeat_padding : binstring
(* TODO: RFC6520 The padding_length MUST be at least 16. *)
}


(* TLS record *)

union record_content (Unparsed_Record, [param context]) =
  | CT_Alert -> Alert of tls_alert
  | CT_Handshake -> Handshake of handshake_msg(context)
  | CT_ChangeCipherSpec -> ChangeCipherSpec of change_cipher_spec
  | CT_ApplicationData -> ApplicationData of binstring
  | CT_Heartbeat -> Heartbeat of heartbeat_msg

struct tls_record [top; param context] = {
  content_type : tls_content_type;
  record_version : tls_version;
  record_content : container[uint16] of record_content (context; _content_type)
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
