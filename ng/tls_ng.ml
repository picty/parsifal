open TlsEnums


(* Simple TLS records *)

record_def tls_alert = {
  alert_level : tls_alert_level;
  alert_type : tls_alert_type
}

record_def change_cipher_spec = {
  change_cipher_spec_value : change_cipher_spec_value
}



(* Handshake records and choices *)

(* Explicit ("name_type") *)
union sni_name (Unparsed_SNIName, [enrich]) =
  | NT_Hostname -> HostName of string(uint16)

record_def server_name = {
  sni_name_type : name_type;
  sni_name : sni_name(_sni_name_type)
}

union server_name_content (Unparsed_ServerNameContent, [enrich; param direction]) =
  | ClientToServer -> ClientServerName of (list(uint16) of server_name)
  | ServerToClient -> ServerServerName

union hello_extension_content (Unparsed_HelloExtension, [enrich; param direction]) =
  | HE_ServerName -> ServerName of (server_name_content(direction))
  | HE_MaxFragmentLength -> MaxFragmentLength of uint8
  | HE_ClientCertificateURL -> ClientCertificateURL
  (* TODO | HE_TrustedCAKeys -> TrustedCAKeys of ? *)
  | HE_TruncatedMAC -> TruncatedMAC
  (* TODO: describe the other extensions! *)

record_def hello_extension [param direction] = {
  extension_type : extension_type;
  extension_data : container(uint16) of hello_extension_content(direction, _extension_type)
}

record_def client_hello = {
  client_version : tls_version;
  client_random : string(32);
  client_session_id : string(uint8);
  ciphersuites : list(uint16) of ciphersuite;
  compression_methods : list(uint8) of compression_method;
  optional client_extensions : list(uint16) of hello_extension(ClientToServer)
}


(* TODO: From here!!! *)



(*   handle_record_desc ("server_hello",        server_hello_d, []); *)
(* let server_hello_d = [ *)
(*   "server_version", FT_Enum ("TlsEnums", "tls_version"), false; *)
(*   "server_random", FT_String (FixedLen 32, true), false; *)
(*   "server_session_id", FT_String (VarLen IT_UInt8, true), false; *)
(*   "ciphersuite", FT_Enum ("TlsEnums", "ciphersuite"), false; *)
(*   "compression_method", FT_Enum ("TlsEnums", "compression_method"), false; *)
(*   "server_extensions", FT_List (VarLen IT_UInt16, FT_Custom (None, "hello_extension", ["ServerToClient"])), true; *)
(* ] *)

(*   handle_record_desc ("new_session_ticket",  new_session_ticket_d, []); *)
(* let new_session_ticket_d = [ *)
(*   "ticket_lifetime_hint", FT_Integer IT_UInt32, false; *)
(*   "ticket", FT_String (VarLen IT_UInt16, true), false; *)
(* ] *)


(*   handle_record_desc ("certificates",        certificates_d, []); *)
(* let certificates_d = [ *)
(*   "certificate_list", FT_List (VarLen IT_UInt24, FT_String (VarLen IT_UInt24, true)), false *)
(* ] *)


(*   handle_record_desc ("server_dh_params",    server_dh_params_d, []); *)
(* let server_dh_params_d = [ *)
(*   "dh_p", FT_String (VarLen IT_UInt16, true), false; *)
(*   "dh_g", FT_String (VarLen IT_UInt16, true), false; *)
(*   "dh_Ys", FT_String (VarLen IT_UInt16, true), false; *)
(* ] *)

(* (\* TODO: signature? *\) *)
(*   handle_record_desc ("ske_dhe_params",      ske_dhe_params_d, []); *)
(* let ske_dhe_params_d = [ *)
(*   "params", FT_Custom (None, "server_dh_params", []), false; *)
(*   "signature", FT_String (Remaining, true), false; *)
(* ] *)

(*   handle_choice_desc ("server_key_exchange", *)
(*           None, Implicit "context.future.s_ciphersuite.kx", *)
(*           server_key_exchange_c, "Unparsed_SKEContent", [CO_EnrichByDefault]); *)
(* let server_key_exchange_c = [ *)
(*   "KX_DHE", "SKE_DHE", FT_Custom (None, "ske_dhe_params", []); *)
(* ] *)

(*   handle_record_desc ("signature_and_hash_algorithm", signature_and_hash_algorithm_d, []); *)
(* let signature_and_hash_algorithm_d = [ *)
(*   "hash_algorithm", FT_Enum ("TlsEnums", "hash_algorithm"), false; *)
(*   "signature_algorithm", FT_Enum ("TlsEnums", "signature_algorithm"), false; *)
(* ] *)

(*   handle_record_desc ("certificate_request", certificate_request_d, []); *)
(* let certificate_request_d = [ *)
(*   "certificate_types", FT_Enum ("TlsEnums", "client_certificate_type"), false; *)
(*   "supported_signature_algorithms", FT_List (VarLen IT_UInt16, FT_Custom (None, "signature_and_hash_algorithm", [])), false; *)
(*   "certificate_authorities", FT_List (VarLen IT_UInt16, FT_String (VarLen IT_UInt16, true)), false; *)
(* ] *)
	

(*   handle_choice_desc ("handshake_content",  *)
(*           Some "TlsEnums", Explicit ("handshake_type"), handshake_content_c, "Unparsed_HSContent", [CO_EnrichByDefault]); *)
(* let handshake_content_c = [ *)
(*   "HT_HelloRequest", "HelloRequest", FT_Custom (None, "hello_request [EMPTY]", []); *)
(*   "HT_ClientHello", "ClientHello", FT_Custom (None, "client_hello", []); *)
(*   "HT_ServerHello", "ServerHello", FT_Custom (None, "server_hello", []); *)
(*   "HT_NewSessionTicket", "NewSessionTicket", FT_Custom (None, "new_session_ticket", []); *)
(*   "HT_Certificate", "Certificate", FT_Custom (None, "certificates", []); *)
(*   "HT_ServerKeyExchange", "ServerKeyExchange", FT_Custom (None, "server_key_exchange", []); *)
(*   "HT_CertificateRequest", "CertificateRequest", FT_Custom (None, "certificate_request", []); *)
(*   "HT_ServerHelloDone", "ServerHelloDone", FT_Custom (None, "server_hello_done", []); *)
(* ] *)

(*   handle_record_desc ("handshake_msg",       handshake_msg_d, []); *)
(* let handshake_msg_d = [ *)
(*   "handshake_type", FT_Enum ("TlsEnums", "hs_message_type"), false; *)
(*   "handshake_content", FT_Container (IT_UInt24, FT_Custom (None, "handshake_content", ["_handshake_type"])), false; *)
(* ] *)


(* (\* TLS record *\) *)

(*   handle_choice_desc ("record_content", *)
(*           Some "TlsEnums", Explicit ("content_type"), record_content_c, "Unparsed_Record", []); *)
(* let record_content_c = [ *)
(*   "CT_Alert", "Alert", FT_Custom (None, "tls_alert", []); *)
(*   "CT_Handshake", "Handshake", FT_Custom (None, "handshake_msg", []); *)
(*   "CT_ChangeCipherSpec", "ChangeCipherSpec", FT_Custom (None, "change_cipher_spec", []); *)
(*   "CT_ApplicationData", "ApplicationData", FT_String (Remaining, true) *)
(* ] *)

(*   handle_record_desc ("tls_record",          tls_record_d, []); *)
(* let tls_record_d = [ *)
(*   "content_type", FT_Enum ("TlsEnums", "tls_content_type"), false; *)
(*   "record_version", FT_Enum ("TlsEnums", "tls_version"), false; *)
(*   "record_content", FT_Container (IT_UInt16, FT_Custom (None, "record_content", ["_content_type"])), false; *)
(* ] *)








(* type ciphersuite_description = { *)
(*   suite_name : TlsEnums.ciphersuite; *)
(*   kx : key_exchange_algorithm; *)
(*   au : authentication_algorithm; *)
(*   enc : encryption_algorithm; *)
(*   mac : integrity_algorithm; *)
(*   prf : pseudo_random_function; *)
(*   export : bool; *)
(*   min_version : int; *)
(*   max_version : int; *)
(* } *)


(* let ciphersuite_descriptions = Hashtbl.create 300 *)

(* let find_csdescr cs = *)
(*   try Hashtbl.find ciphersuite_descriptions cs *)
(*   with Not_found -> { *)
(*     suite_name = cs; *)
(*     kx = KX_Unknown; au = AU_Unknown; *)
(*     enc = ENC_Unknown; mac = MAC_Unknown; *)
(*     prf = PRF_Unknown; *)
(*     export = false; min_version = 0; max_version = 0xffff; *)
(*   } *)


(* type crypto_context = { *)
(*   mutable versions_proposed : TlsEnums.tls_version * TlsEnums.tls_version; *)
(*   mutable ciphersuites_proposed : TlsEnums.ciphersuite list; *)
(*   mutable compressions_proposed : TlsEnums.compression_method list; *)

(*   mutable s_version : TlsEnums.tls_version; *)
(*   mutable s_ciphersuite : ciphersuite_description; *)
(*   mutable s_compression_method : TlsEnums.compression_method; *)

(*   mutable s_server_key_exchange : server_key_exchange; *)

(*   mutable s_client_random : string; *)
(*   mutable s_server_random : string; *)
(*   mutable s_session_id : string; *)
(* } *)

(* type tls_context = { *)
(*   mutable present : crypto_context; *)
(*   mutable future : crypto_context; *)
(* } *)

(* let empty_crypto_context () = { *)
(*   versions_proposed = TlsEnums.V_Unknown 0xffff, TlsEnums.V_Unknown 0; *)
(*   ciphersuites_proposed = []; *)
(*   compressions_proposed = []; *)

(*   s_version = TlsEnums.V_Unknown 0; *)
(*   s_ciphersuite = find_csdescr TlsEnums.TLS_NULL_WITH_NULL_NULL; *)
(*   s_compression_method = TlsEnums.CM_Null; *)

(*   s_server_key_exchange = Unparsed_SKEContent ""; *)

(*   s_client_random = ""; *)
(*   s_server_random = ""; *)
(*   s_session_id = ""; *)
(* } *)

(* let empty_context () = { *)
(*   present = empty_crypto_context (); *)
(*   future = empty_crypto_context (); *)
(* } *)


(* let check_record_version ctx record_version = *)
(*   ctx.present.s_version = (TlsEnums.V_Unknown 0) || *)
(*   ctx.present.s_version = record_version *)
