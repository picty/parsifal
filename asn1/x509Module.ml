open Types
open Modules
open X509
open X509Directory
open X509Extensions

module DNParser = struct
  type t = dn
  let name = "distinguished_name"

  let resolve_names = ref true
  let params = [
    param_from_bool_ref "_resolve_names" resolve_names
  ]


  let get_name_resolver () =
    if !resolve_names
    then Some name_directory
    else None


  (* TODO: Should disappear soon... *)
  type pstate = Asn1.Engine.parsing_state
  let pstate_of_string = Asn1.Engine.pstate_of_string "(inline)"
  let pstate_of_stream = Asn1.Engine.pstate_of_stream
  let eos = Asn1.Engine.eos
  (* TODO: End of blob *)

  let mk_ehf _ = raise NotImplemented

  let parse pstate =
    try
      Asn1Constraints.constrained_parse_opt (dn_constraint object_directory name)
	ParsingEngine.s_specfatallyviolated pstate
    with
      | ParsingEngine.OutOfBounds s ->
	output_string stderr ("Out of bounds in " ^ s ^ ")");
	flush stderr;
	None
      | Asn1.Engine.ParsingError (err, sev, pstate) ->
	output_string stderr ("Parsing error: " ^ (Asn1.Engine.string_of_exception err sev pstate) ^ "\n");
	flush stderr;
	None

  let dump dn = raise NotImplemented

  let enrich dn dict =
    let rec handle_atv = function
      | [] -> ()
      | atv::r ->
	let oid = Asn1.string_of_oid (get_name_resolver ()) atv.oo_id in
	let value =
	  match atv.oo_content with
	    | None -> V_Unit
	    | Some o -> Asn1Module.value_of_asn1_content o
	in
        (* Add code to retain the order of the ATVs, and the asn1 class and tag of the objects -> needed for update *)
	Hashtbl.add dict oid value;
	handle_atv r
    in
    handle_atv (List.flatten dn)

  let update dict = raise NotImplemented

  let to_string dn = string_of_dn "" (get_name_resolver ()) dn
end

module DNModule = MakeParserModule (DNParser)
let _ = add_module ((module DNModule : Module))




module DateTimeParser = struct
  type t = datetime_content
  let name = "date_time"
  let params = []

  type pstate = unit
  let pstate_of_string _ = raise NotImplemented
  let pstate_of_stream _ _ = raise NotImplemented
  let eos _ = raise NotImplemented
  let mk_ehf _ = raise NotImplemented
  let parse _ = raise NotImplemented
  let dump _ = raise NotImplemented
  let update _ = raise NotImplemented

  let enrich dt dict =
    Hashtbl.replace dict "year" (V_Int dt.year);
    Hashtbl.replace dict "month" (V_Int dt.month);
    Hashtbl.replace dict "day" (V_Int dt.day);
    Hashtbl.replace dict "hour" (V_Int dt.hour);
    Hashtbl.replace dict "minute" (V_Int dt.minute);
    match dt.second with
      | None -> ()
      | Some sec -> Hashtbl.replace dict "second" (V_Int sec)

  let to_string o = string_of_datetime (Some o)
end

module DateTimeModule = MakeParserModule (DateTimeParser)
let _ = add_module ((module DateTimeModule : Module))




module X509Parser = struct
  type t = certificate
  let name = "x509"
  let params = []

  (* TODO: Should disappear soon... *)
  type pstate = Asn1.Engine.parsing_state
  let pstate_of_string = Asn1.Engine.pstate_of_string "(inline)"
  let eos = Asn1.Engine.eos
  let pstate_of_stream = Asn1.Engine.pstate_of_stream
  (* TODO: End of blob *)

  let mk_ehf _ = raise NotImplemented

  let parse pstate =
    try
      Asn1Constraints.constrained_parse_opt (certificate_constraint object_directory)
	ParsingEngine.s_specfatallyviolated pstate
    with
      | ParsingEngine.OutOfBounds s ->
	output_string stderr ("Out of bounds in " ^ s ^ ")");
	flush stderr;
	None
      | Asn1.Engine.ParsingError (err, sev, pstate) ->
	output_string stderr ("Parsing error: " ^ (Asn1.Engine.string_of_exception err sev pstate) ^ "\n");
	flush stderr;
	None

  let dump cert = raise NotImplemented

  let enrich cert dict =
    let handle_unique_id id_name = function
      | None -> ()
      | Some (n, s) -> Hashtbl.replace  dict id_name (V_BitString (n, s))
    in
    let handle_datetime id_name = function
      | None -> ()
      | Some dt ->
	let datetime_value = DateTimeModule.register dt in
	Hashtbl.replace dict id_name datetime_value
    in

    (* TODO: Add all the missing fields! *)
    begin
      match cert.tbs.version with
	| None -> ()
	| Some v -> Hashtbl.replace dict "version" (V_Int v)
    end;
    Hashtbl.replace dict "serial" (V_Bigint cert.tbs.serial);

    (* sigalgo *)

    let issuer_value = DNModule.register cert.tbs.issuer in
    Hashtbl.replace dict "issuer" issuer_value;

    handle_datetime "not_before" cert.tbs.validity.not_before;
    handle_datetime "not_after" cert.tbs.validity.not_after;

    let subject_value = DNModule.register cert.tbs.subject in
    Hashtbl.replace dict "subject" subject_value;

    (* cert.tbs.public_key_info.pk_algo *)
    begin
      match cert.tbs.pk_info.public_key with
	| PK_DSA {dsa_p; dsa_q; dsa_g; dsa_Y} ->
	  Hashtbl.replace dict "key_type" (V_String "DSA");
	  Hashtbl.replace dict "p" (V_Bigint dsa_p);
	  Hashtbl.replace dict "q" (V_Bigint dsa_q);
	  Hashtbl.replace dict "g" (V_Bigint dsa_g);
	  Hashtbl.replace dict "Y" (V_Bigint dsa_Y)
	| PK_RSA {rsa_n; rsa_e} ->
	  Hashtbl.replace dict "key_type" (V_String "RSA");
	  Hashtbl.replace dict "n" (V_Bigint rsa_n);
	  Hashtbl.replace dict "e" (V_Bigint rsa_e)
	| PK_WrongPKInfo ->
	  Hashtbl.replace dict "key_type" (V_String "WrongPKInfo");
	| PK_Unparsed _ ->
	  Hashtbl.replace dict "key_type" (V_String "UnparsedPKInfo");
    end;

    handle_unique_id "issuer_unique_id" cert.tbs.issuer_unique_id;
    handle_unique_id "subject_unique_id" cert.tbs.subject_unique_id;
    (* extensions *)
    (* cert_sig_algo *)
    begin
      match cert.signature with
	| Sig_DSA {dsa_r; dsa_s} ->
	  Hashtbl.replace dict "sig_type" (V_String "DSA");
	  Hashtbl.replace dict "r" (V_Bigint dsa_r);
	  Hashtbl.replace dict "s" (V_Bigint dsa_s)
	| Sig_RSA rsa_s ->
	  Hashtbl.replace dict "sig_type" (V_String "RSA");
	  Hashtbl.replace dict "s" (V_Bigint rsa_s)
	| Sig_WrongSignature ->
	  Hashtbl.replace dict "key_type" (V_String "WrongSignature");
	| Sig_Unparsed _ ->
	  Hashtbl.replace dict "key_type" (V_String "UnparsedSignature");
    end	;
    ()

  let update dict = raise NotImplemented

  (* TODO : resolver *)
  let to_string cert = string_of_certificate true "" (Some name_directory) cert
end

module X509Module = MakeParserModule (X509Parser)
let _ = add_module ((module X509Module : Module))
