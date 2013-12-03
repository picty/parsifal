open BasePTypes
open PTypes
open TlsEnums


(* Suite description *)

type ciphersuite_description = {
  suite_name : ciphersuite;
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




(* Simple TLS records *)

struct tls_alert = {
  alert_level : tls_alert_level;
  alert_type : tls_alert_type
}

struct change_cipher_spec = {
  change_cipher_spec_value : change_cipher_spec_value
}



(* Handshake extensions records and choices *)

(* Explicit ("name_type") *)
union sni_name [enrich] (Unparsed_SNIName) =
  | NT_HostName -> HostName of string[uint16]

struct server_name = {
  sni_name_type : name_type;
  sni_name : sni_name(sni_name_type)
}

union server_name_content [enrich; exhaustive] (Unparsed_ServerNameContent) =
  | ClientToServer -> ClientServerName of (list[uint16] of server_name)
  | ServerToClient -> ServerServerName

struct url_and_hash = {
  url : string[uint16];
  padding : PTypes.magic ("\x01");   (* RFC 6066 states this for backward compatibility *)
  sha1_hash : binstring(20)
}

struct certificate_url = {
  cert_chain_type : cert_chain_type;
  url_and_hash_list : list[uint16] of url_and_hash
}

union identifier [enrich] (Unparsed_Identifier) =
  | IT_PreAgreed -> PreAgreed
  | IT_KeySha1Hash -> KeySha1Hash of binstring(20)
  | IT_X509Name -> X509Name of X509Basics.distinguishedName
  | IT_CertSha1Hash -> CertSha1Hash of binstring(20)

struct trusted_authority = {
  identifier_type : identifier_type;
  identifier : identifier (identifier_type)
}


(* TODO: Implement the commented extensions *)
union hello_extension_content [enrich; param direction] (Unparsed_HelloExtension) =
  | HE_ServerName -> ServerName of server_name_content(direction)
  | HE_MaxFragmentLength -> MaxFragmentLength of max_fragment_length
  | HE_ClientCertificateURL -> ClientCertificateURL
  | HE_TrustedCAKeys -> TrustedCAKeys of list[uint16] of trusted_authority
  | HE_TruncatedMAC -> TruncatedMAC
  (* | HE_StatusRequest -> StatusRequest of ? *)
  (* | HE_UserMapping -> UserMapping of ? *)
  (* | HE_ClientAuthz -> ClientAuthz of ? *)
  (* | HE_ServerAuthz -> ServerAuthz of ? *)
  (* | HE_CertType -> CertType of ? *)
  | HE_EllipticCurves -> EllipticCurves of (list[uint16] of ec_named_curve)
  | HE_ECPointFormats -> ECPointFormats of (list[uint8] of ec_point_format)
  (* | HE_SRP -> SRPExtension of ? *)
  (* | HE_SignatureAlgorithms -> SignatureAlgorithms of ? *)
  (* | HE_UseSRTP -> UseSRTP of ? *)
  | HE_Heartbeat -> HeartbeatExtension of heartbeat_mode
  | HE_SessionTicket -> SessionTicket of binstring
  | HE_RenegotiationInfo -> RenegotiationInfo of binstring



(* Handshake messages *)

struct hello_extension [param direction] = {
  extension_type : extension_type;
  extension_data : container[uint16] of hello_extension_content(direction; extension_type)
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

let enrich_certificate_in_certificates = ref false
alias certificates = list[uint24] of container[uint24] of
    trivial_union(enrich_certificate_in_certificates) of X509.certificate


(* DHE *)
struct server_dh_params = {
  dh_p : binstring[uint16];
  dh_g : binstring[uint16];
  dh_Ys: binstring[uint16]
}

struct ske_dhe_params = {
  params : server_dh_params;
  signature : binstring (* TODO? *)
}


(* ECDHE *)
struct ec_curve = {
  ecc_a : binstring[uint8];
  ecc_b : binstring[uint8]
}

alias ec_point = binstring[uint8]

struct ec_explicit_prime_params = {
  ecpp_prime_p : binstring[uint8];
  ecpp_curve : ec_curve;
  ecpp_base : ec_point;
  ecpp_order : binstring[uint8];
  ecpp_cofactor : binstring[uint8]
}

(* TODO (from RFC4492):
   enum { ec_basis_trinomial, ec_basis_pentanomial } ECBasisType;
   ECBasisType basis;

   select (basis) {
       case ec_trinomial:
         opaque  k <1..2^8-1>;
       case ec_pentanomial:
         opaque  k1 <1..2^8-1>;
         opaque  k2 <1..2^8-1>;
         opaque  k3 <1..2^8-1>;
     };

struct ec_explicit_char2_params = {
   ecp2_m : uint16;
   ecp2_basis : ec_basis_type; (* TODO *)
   ecp2_ks : ec_basis_type_definition(ec_basic_type); (* TODO *)
   ecp2_curve : ec_curve;
   ecp2_base : ec_point;
   ecp2_order : binstring[uint8];
   ecp2_cofactor : binstring[uint8];
} *)

union ec_curve_params [enrich] (UnknownECCurveParams) =
  | ECCT_ExplicitPrime -> ECP_ExplicitPrime of ec_explicit_prime_params
(*  | ECCT_ExplicitChar2 -> TODO? *)
  | ECCT_NamedCurve -> ECP_NamedCurve of ec_named_curve

(* Here, we took some liberty with RFC4492 and merged
   ServerECDHParams and ECParameters structures *)
struct server_ecdh_params = {
  ecdh_type : ec_curve_type;
  ecdh_params : ec_curve_params (ecdh_type);
  ecdh_public : ec_point
}

(* TODO: Clean up this stupid prefix once field desambiguation is mainstream... *)
struct ske_ecdhe_params = {
  ecdhe_params : server_ecdh_params;
  ecdhe_signature : binstring (* TODO? *)
}


union server_key_exchange [enrich] (Unparsed_SKEContent) =
  | KX_DHE -> SKE_DHE of ske_dhe_params
  | KX_ECDHE -> SKE_ECDHE of ske_ecdhe_params




type prefs = {
  acceptable_versions : tls_version * tls_version;
  acceptable_ciphersuites : ciphersuite list;
  acceptable_compressions : compression_method list;
  directive_behaviour : bool;
}

let default_prefs = {
  acceptable_versions = (V_SSLv3, V_TLSv1_2);
  acceptable_ciphersuites = [TLS_RSA_WITH_RC4_128_SHA];
  acceptable_compressions = [CM_Null];
  directive_behaviour = false;
}


type future_crypto_context = {
  mutable proposed_versions : tls_version * tls_version;
  mutable proposed_ciphersuites : ciphersuite list;
  mutable proposed_compressions : compression_method list;

  mutable s_certificates : (X509.certificate trivial_union) list;
  mutable s_server_key_exchange : server_key_exchange; (* this should NOT be a server_key_exchange *)
  mutable s_client_random : string;
  mutable s_server_random : string;
  mutable s_session_id : string;
}

type tls_context = {
  mutable current_version : tls_version;
  mutable current_ciphersuite : ciphersuite_description;
  mutable current_compression_method : compression_method;

  mutable current_randoms : string * string;
  mutable current_master_secret : string;

  mutable out_compress : string -> string;
  mutable out_encrypt : string -> string;

  mutable in_decrypt : string -> string;
  mutable in_expand : string -> string;

  future : future_crypto_context;
}

struct signature_and_hash_algorithm = {
  hash_algorithm : hash_algorithm;
  signature_algorithm : signature_algorithm
}


let enrich_distinguishedName_in_certificate_request = ref false
struct certificate_request = {
  certificate_types : list[uint8] of client_certificate_type;
  supported_signature_algorithms : list[uint16] of signature_and_hash_algorithm;
  certificate_authorities : list[uint16] of container[uint16] of
      trivial_union(enrich_distinguishedName_in_certificate_request) of X509Basics.distinguishedName
}

let extract_future_kx = function
  | Some {future = {proposed_ciphersuites = [cs]} } -> (find_csdescr cs).kx
  | _ -> KX_Unknown

union handshake_content [enrich; param context] (Unparsed_HSContent) =
  | HT_HelloRequest -> HelloRequest
  | HT_ClientHello -> ClientHello of client_hello
  | HT_ServerHello -> ServerHello of server_hello
 (* | HT_HelloVerifyRequest -> HelloVerifyRequest of *)
  | HT_NewSessionTicket -> NewSessionTicket of new_session_ticket
  | HT_Certificate -> Certificate of certificates
  | HT_ServerKeyExchange -> ServerKeyExchange of server_key_exchange(extract_future_kx context)
  | HT_CertificateRequest -> CertificateRequest of certificate_request
  | HT_ServerHelloDone -> ServerHelloDone
 (* | HT_CertificateVerify -> CertificateVerify of *)
 (* | HT_ClientKeyExchange -> ClientKeyExchange of *)
 (* | HT_Finished -> Finished of *)
  | HT_CertificateURL -> CertificateURL of certificate_url
 (* | HT_CertificateStatus -> CertificateStatus of *)
  | HT_SupplementalData -> SupplementalData of binstring[uint24]


struct handshake_msg [param context] = {
  handshake_type : hs_message_type;
  handshake_content : container[uint24] of handshake_content(context; handshake_type)
}

struct heartbeat_msg = {
  heartbeat_message_type : heartbeat_message_type;
  heartbeat_payload : binstring[uint16];
  heartbeat_padding : binstring
(* TODO: RFC6520 The padding_length MUST be at least 16. *)
}


(* TLS record *)

union record_content [param context; exhaustive; top] (Unparsed_Record) =
  | CT_Alert -> Alert of tls_alert
  | CT_Handshake -> Handshake of handshake_msg(context)
  | CT_ChangeCipherSpec -> ChangeCipherSpec of change_cipher_spec
  | CT_ApplicationData -> ApplicationData of binstring
  | CT_Heartbeat -> Heartbeat of heartbeat_msg

struct tls_record [top; param context] = {
  content_type : tls_content_type;
  record_version : tls_version;
  record_content : container[uint16] of record_content (context; content_type)
}


let empty_future_crypto_context prefs = {
  proposed_versions = prefs.acceptable_versions;
  proposed_ciphersuites = prefs.acceptable_ciphersuites;
  proposed_compressions = prefs.acceptable_compressions;

  s_certificates = [];
  s_server_key_exchange = Unparsed_SKEContent "";
  s_client_random = ""; s_server_random = "";
  s_session_id = "";
}


let id x = x

let empty_context prefs = {
  current_version = fst prefs.acceptable_versions;  (* And SSLv2? *)
  current_ciphersuite = find_csdescr TLS_NULL_WITH_NULL_NULL;
  current_compression_method = CM_Null;

  current_randoms = "", "";
  current_master_secret = "";
  out_compress = id; out_encrypt = id;
  in_decrypt = id; in_expand = id;

  future = empty_future_crypto_context prefs;
}

