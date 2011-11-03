open Types
open Modules
open OldTls

module TlsParser = struct
  type t = record
  let name = "old_tls"

  let parse_extensions  = ref true
  let params = [
    param_from_int_ref "_tolerance" Engine.tolerance;
    param_from_int_ref "_minDisplay" Engine.minDisplay;
    param_from_bool_ref "_parse_extensions" parse_extensions;
  ]


  (* TODO: Should disappear soon... *)
  type pstate = Engine.parsing_state
  let pstate_of_string = Engine.pstate_of_string "(inline)"
  let pstate_of_stream = Engine.pstate_of_stream
  (* TODO: End of blob *)

  let parse pstate =
    try
      Some (parse_record !parse_extensions pstate)
    with 
      | ParsingEngine.OutOfBounds s ->
	output_string stderr ("Out of bounds in " ^ s ^ ")");
	flush stderr;
	None
      | Engine.ParsingError (err, sev, pstate) ->
	output_string stderr ("Parsing error: " ^ (Engine.string_of_exception err sev pstate) ^ "\n");
	flush stderr;
	None

  let dump r = raise NotImplemented

  let enrich record dict =
    Hashtbl.replace dict "content_type"
      (V_String (string_of_content_type (type_of_record_content record.content)));
    Hashtbl.replace dict "version" (V_String (string_of_protocol_version record.version));

    match record.content with
      | Handshake [h] ->
	Hashtbl.replace dict "handshake_msg_type"
	  (V_String (string_of_handshake_msg_type (type_of_handshake_msg h)));
	begin
	  match h with
	    | ClientHello ch ->
	      Hashtbl.replace dict "ch_version" (V_String (string_of_protocol_version ch.c_version));
	      Hashtbl.replace dict "random" (V_BinaryString ch.c_random);
	      Hashtbl.replace dict "session_id" (V_BinaryString ch.c_session_id);
	      Hashtbl.replace dict "ciphersuites"
		(V_List (List.map (fun x -> V_Int x) ch.c_cipher_suites));
	      Hashtbl.replace dict "compression_methods"
		(V_List (List.map (fun x -> V_Int (int_of_compression_method x)) ch.c_compression_methods));
	      ()  (* TODO: Extensions *)
	    | ServerHello sh ->
	      Hashtbl.replace dict "sh_version" (V_String (string_of_protocol_version sh.s_version));
	      Hashtbl.replace dict "random" (V_BinaryString sh.s_random);
	      Hashtbl.replace dict "session_id" (V_BinaryString sh.s_session_id);
	      Hashtbl.replace dict "ciphersuite" (V_Int sh.s_cipher_suite);
	      Hashtbl.replace dict "compression_method" (V_Int (int_of_compression_method sh.s_compression_method));
	      ()  (* TODO: Extensions *)
	    | Certificate certs ->
	      let certs = List.map X509Module.X509Module.register certs in
	      Hashtbl.replace dict "certificates" (V_List certs)
	    | _ -> ()
	end
      | Alert (level, t) ->
	Hashtbl.replace dict "alert_level" (V_String (string_of_alert_level level));
	Hashtbl.replace dict "alert_type" (V_String (string_of_alert_type t))
      | _ -> ()

  let update dict = raise NotImplemented

  let to_string = string_of_record
end

module TlsModule = MakeParserModule (TlsParser)
let _ = add_module ((module TlsModule : Module))
