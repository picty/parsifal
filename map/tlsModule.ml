open MapEval
open MapModule
open Tls


module TlsParser = struct
  type t = record
  let name = "tls"
  let params : (string, value) Hashtbl.t = Hashtbl.create 10

  let init () =
    Hashtbl.replace params "_tolerance" (V_Int TlsEngineParams.s_fatal);
    Hashtbl.replace params "_minDisplay" (V_Int 0);
    Hashtbl.replace params "_parse_extensions" (V_Bool true)

  let parse name stream =
    let asn1_tolerance = eval_as_int (Hashtbl.find Asn1Module.Asn1Parser.params "_tolerance")
    and asn1_minDisplay = eval_as_int (Hashtbl.find Asn1Module.Asn1Parser.params "_minDisplay") in
    let asn1_ehf = Asn1.Engine.default_error_handling_function asn1_tolerance asn1_minDisplay in
    let tolerance = eval_as_int (Hashtbl.find params "_tolerance")
    and minDisplay = eval_as_int (Hashtbl.find params "_minDisplay")
    and parse_exts = eval_as_bool (Hashtbl.find params "_parse_extensions") in
    let ehf = Engine.default_error_handling_function tolerance minDisplay in
    let pstate = Engine.pstate_of_stream ehf name stream in
    try
      Some (parse_record asn1_ehf parse_exts pstate)
    with 
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
      | Handshake h ->
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

module TlsModule = Make (TlsParser)
let _ = add_module ((module TlsModule : MapModule))
