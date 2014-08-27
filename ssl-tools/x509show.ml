open Parsifal
open Asn1PTypes
open Pkcs1
open X509Basics
open X509Extensions
open X509
open X509Util
open Getopt

type action =
  | Text | PrettyPrint | JSON | Dump | BinDump
  | Subject | Issuer | Serial | Modulus
  | CheckSelfSigned | Get of string | HTTPNames
  | CheckLink | RFCCheckChain | BuildChains
let action = ref Text
let set_action value = TrivialFun (fun () -> action := value)

type print_name = Default | PrintName | DoNotPrintName
let print_names = ref Default
let set_print_names value = TrivialFun (fun () -> print_names := value)

let verbose = ref false
let keep_going = ref false
let base64 = ref true

let do_get_action path =
  action := Get path;
  ActionDone

let cas = ref []
let intermediate_cas = ref []
let add_to_list l elt =
  l := elt::!l;
  ActionDone

let options = [
  mkopt (Some 'h') "help" Usage "show this help";
  mkopt (Some 'v') "verbose" (Set verbose) "print more info to stderr";
  mkopt (Some 'k') "keep-going" (Set keep_going) "keep working even when errors arise";
  mkopt None "pem" (Set base64) "use PEM format (default)";
  mkopt None "der" (Clear base64) "use DER format";

  mkopt (Some 't') "text" (set_action Text) "prints the certificates given";
  mkopt (Some 'p') "pretty-print" (set_action PrettyPrint) "prints the certificates given";
  mkopt None "json" (set_action JSON) "prints the certificate given, JSON style";
  mkopt (Some 'D') "dump" (set_action Dump) "dumps the certificates given (in hexa)";
  mkopt None "binary-dump" (set_action BinDump) "dumps the certificates given";
  mkopt (Some 'S') "serial" (set_action Serial) "prints the certificates serial number";
  mkopt (Some 's') "subject" (set_action Subject) "prints the certificates subject";
  mkopt (Some 'i') "issuer" (set_action Issuer) "prints the certificates issuer";
  mkopt (Some 'm') "modulus" (set_action Modulus) "prints the RSA modulus";
  mkopt (Some 'N') "http-names" (set_action HTTPNames) "prints the CN/IP/DNS embedded";
  mkopt None "check-selfsigned" (set_action CheckSelfSigned) "checks the signature of a self signed";
  mkopt (Some 'g') "get" (StringFun do_get_action) "walks through the certificate using a get string";
  mkopt (Some 'L') "link" (set_action CheckLink) "checks the link between an authority and potential subjets";
  mkopt None "rfc-check" (set_action RFCCheckChain) "checks whether a given list of certificates are a valid RFC chain";
  mkopt (Some 'C') "build-chains" (set_action BuildChains) "checks whether a given list of certificates are a valid RFC chain";

  mkopt (Some 'n') "numeric" (Clear resolve_oids) "show numerical fields (do not resolve OIds)";
  mkopt None "resolve-oids" (Set resolve_oids) "show OID names";
  mkopt None "ca" (StringFun (add_to_list cas)) "select a trusted CA file";
  mkopt None "intermediate-ca" (StringFun (add_to_list intermediate_cas)) "select an intermediate CA file";

  mkopt None "print-names" (set_print_names PrintName) "always prefix the answer with the filename";
  mkopt None "dont-print-names" (set_print_names DoNotPrintName) "never prefix the answer with the filename";

  mkopt None "dont-parse-extensions" (Clear enrich_extnValue) "do not try and enrich extensions";
  mkopt None "dont-parse-public-keys" (Clear enrich_subjectPublicKey) "do not try and enrich subject public keys";
  mkopt None "dont-parse-signatures" (Clear enrich_signature) "do not try and enrich signature fields";
  mkopt None "dont-parse-algo-params" (Clear enrich_algorithmParams) "do not try and enrich algorithm params";
]


let pretty_print_pubkey pk =
  let pk_type = string_of_der_oid_content pk.algorithm.algorithmId
  and pk_params = match pk.algorithm.algorithmParams with
    | Some (NoParams ()) | None -> []
    | Some p ->
      Str.split (Str.regexp_string "\n") (print_value ~name:"params" (value_of_algorithmParams p))
  and pk_value =
    Str.split (Str.regexp_string "\n") (print_value ~name:"public key"(value_of_subjectPublicKey pk.subjectPublicKey))
  in
  ""::"Public key"::(List.map (fun s -> "  " ^ s) ((pk_type::pk_params)@pk_value))

let pretty_print_extension opts e =
  let _name = string_of_der_oid_content e.extnID in
  let name = if e.critical = (Some true) then _name ^ " (critical)" else _name in
  Str.split (Str.regexp_string "\n") (print_value ~options:opts ~name:name (value_of_extnValue e.extnValue))

let pretty_print_extensions = function
  | None -> []
  | Some es ->
    let opts = incr_indent default_output_options in
    ""::"Extensions"::(List.flatten (List.map (pretty_print_extension opts) es))

let pretty_print_certificate cert =
  let tbs = cert.tbsCertificate in
  if tbs.signature <> cert.signatureAlgorithm
  then ();  (* TODO *)
  [
    (match tbs.version with
    | None -> "Version: no version given, 1 assumed"
    | Some v -> Printf.sprintf "Version: %d" (v+1));

    ""; Printf.sprintf "Serial number: %s" (hexdump tbs.serialNumber);

    ""; Printf.sprintf "Signature: %s" (string_of_oid tbs.signature.algorithmId); (* TODO: Params *)
    ""; Printf.sprintf "Issuer: %s" (string_of_distinguishedName tbs.issuer);
    ""; "Validity";
    Printf.sprintf "    Not before: %s" (string_of_value (value_of_der_time tbs.validity.notBefore));
    Printf.sprintf "    Not after: %s" (string_of_value (value_of_der_time tbs.validity.notAfter));
    ""; Printf.sprintf "Subject: %s" (string_of_distinguishedName tbs.subject);
  ]@
    (pretty_print_pubkey tbs.subjectPublicKeyInfo)@
    (* TODO: unique issuer/subject identifiers? *)
    (pretty_print_extensions tbs.extensions)


let parse_and_number i filename =
  let sc = sc_of_input !base64 false (string_input_of_filename filename) in
  sc.pos_in_hs_msg <- Some i;
  sc


let load_cas store trusted filenames =
  let cas = List.map
    (fun ca_fn -> sc_of_input !base64 trusted (string_input_of_filename ca_fn))
    filenames
  in
  List.iter (add_to_store store) cas


let handle_input input =
  let sc = sc_of_input !base64 false input in
  let certificate = cert_of_sc sc in
  let display = match !action with
    | Serial -> [hexdump certificate.tbsCertificate.serialNumber]
    | CheckSelfSigned ->
      let result = match certificate.tbsCertificate_raw,
	certificate.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey,
	certificate.signatureValue
	with
	| Some m, RSA {p_modulus = n; p_publicExponent = e}, RSASignature s ->
	  (try Pkcs1.raw_verify 1 m s n e with Pkcs1.PaddingError -> false)
	| _ -> false
      in [string_of_bool (result)]
    | Subject -> ["[" ^ String.concat ", " (List.map string_of_atv (List.flatten certificate.tbsCertificate.subject)) ^ "]"]
    | Issuer -> ["[" ^ String.concat ", " (List.map string_of_atv (List.flatten certificate.tbsCertificate.issuer)) ^ "]"]
    | HTTPNames ->
      let names = extract_dns_and_ips certificate in
      List.map (fun (t, v) -> t ^ "=" ^ (quote_string v)) names
    | Modulus ->
      let result = match certificate.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey with
	| RSA {p_modulus = n} -> hexdump n
	| _ -> "No RSA modulus found or parsed"
      in [result]
    | BinDump -> [exact_dump_certificate certificate]
    | Dump -> [hexdump (exact_dump_certificate certificate)]
    | Text -> Str.split (Str.regexp_string "\n")
      (print_value ~options:{ default_output_options with oo_verbose = !verbose }
	 (value_of_certificate certificate))
    | PrettyPrint -> pretty_print_certificate certificate
    | JSON -> Str.split (Str.regexp_string "\n")
      (Json.json_of_value ~options:{ default_output_options with oo_verbose = !verbose }
	 (value_of_certificate certificate))
    | Get path ->
      begin
        match get (value_of_certificate certificate) path with
        | Left _ -> []
        | Right s -> [s]
      end
    | CheckLink | RFCCheckChain | BuildChains ->
      failwith "Internal error: those actions should not be handled here."
  in
  match !print_names with
    | Default ->
      not_implemented "handle_input can not determine wether filenames should be printed"
    | PrintName ->
      let print_line l = Printf.printf "%s:%s\n" input.cur_name l in
      List.iter print_line display
    | DoNotPrintName ->
      List.iter print_endline display

let rec iter_on_names = function
  | [] -> ()
  | f::r ->
    let i = string_input_of_filename f in
    begin
      try handle_input i
      with e ->
	if !keep_going
	then prerr_endline (Printexc.to_string e)
	else raise e
    end;
    iter_on_names r


let _ =
  let args = parse_args ~progname:"x509show" options Sys.argv in
  try
    match !action, args with
    | CheckLink, issuer_fn::(_::_ as subject_fns) ->
      let issuer = sc_of_input !base64 false (string_input_of_filename issuer_fn) in
      let handle_one_subject subject_fn =
        let subject = sc_of_input !base64 false (string_input_of_filename subject_fn) in
        let res = match check_link (cert_of_sc issuer) (cert_of_sc subject) with
	  | [] -> "OK"
	  | l -> String.concat "\n  " (List.map string_of_validation_error l)
        in print_endline (subject_fn ^ ": " ^ res)
      in
      List.iter handle_one_subject subject_fns

    | CheckLink, _ ->
      usage "x509show" options (Some "Please provide at least two certificates with --link")

    | RFCCheckChain, _ ->
      let ca_store = X509Util.mk_cert_store 100 in
      load_cas ca_store true (List.rev !cas);
      let parsed_certs = List.mapi parse_and_number args in
      print_chain (check_rfc_certchain parsed_certs ca_store)

    | BuildChains, _ ->
      let ca_store = X509Util.mk_cert_store 100 in
      load_cas ca_store true (List.rev !cas);
      load_cas ca_store false (List.rev !intermediate_cas);
      let parsed_certs = List.mapi parse_and_number args in
      let chains = build_certchain parsed_certs ca_store in
      List.iter
        (fun (g, c) -> print_endline g; print_chain c; print_newline ())
        (rate_and_sort_chains chains)

    | _, [] ->
      if !print_names = Default then print_names := DoNotPrintName;
      handle_input (string_input_of_stdin ())
    | _, [_] ->
      if !print_names = Default then print_names := DoNotPrintName;
      iter_on_names args
    | _, _ ->
      if !print_names = Default then print_names := PrintName;
      iter_on_names args
  with
    | ParsingException (e, h) -> prerr_endline (string_of_exception e h); exit 1
    | e -> prerr_endline (Printexc.to_string e); exit 1
