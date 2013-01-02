open Lwt
open Parsifal
open Asn1PTypes
open RSAKey
open X509
open Getopt

type action =
  | Text | PrettyPrint | Dump | BinDump
  | Subject | Issuer | Serial | Modulus
  | CheckSelfSigned
let action = ref Text
let set_action value = TrivialFun (fun () -> action := value)

type print_name = Default | PrintName | DoNotPrintName
let print_names = ref Default
let set_print_names value = TrivialFun (fun () -> print_names := value)

let verbose = ref false
let keep_going = ref false

let options = [
  mkopt (Some 'h') "help" Usage "show this help";
  mkopt (Some 'v') "verbose" (Set verbose) "print more info to stderr";
  mkopt (Some 'k') "keep-going" (Set keep_going) "keep working even when errors arise";

  mkopt (Some 't') "text" (set_action Text) "prints the certificates given";
  mkopt (Some 'p') "pretty-print" (set_action PrettyPrint) "prints the certificates given";
  mkopt (Some 'D') "dump" (set_action Dump) "dumps the certificates given (in hexa)";
  mkopt None "binary-dump" (set_action BinDump) "dumps the certificates given";
  mkopt (Some 'S') "serial" (set_action Serial) "prints the certificates serial number";
  mkopt (Some 's') "subject" (set_action Subject) "prints the certificates subject";
  mkopt (Some 'i') "issuer" (set_action Issuer) "prints the certificates issuer";
  mkopt (Some 'm') "modulus" (set_action Modulus) "prints the RSA modulus";
  mkopt None "check-selfsigned" (set_action CheckSelfSigned) "checks the signature of a self signed";

  mkopt (Some 'n') "numeric" (Clear resolve_oids) "show numerical fields (do not resolve OIds)";
  mkopt None "resolve-oids" (Set resolve_oids) "show OID names";

  mkopt None "print-names" (set_print_names PrintName) "always prefix the answer with the filename";
  mkopt None "dont-print-names" (set_print_names DoNotPrintName) "never prefix the answer with the filename";

  mkopt None "dont-parse-extensions" (Clear enrich_extnValue) "do not try and enrich extensions";
  mkopt None "dont-parse-public-keys" (Clear enrich_subjectPublicKey) "do not try and enrich subject public keys";
  mkopt None "dont-parse-signatures" (Clear enrich_signature) "do not try and enrich signature fields";
  mkopt None "dont-parse-algo-params" (Clear enrich_algorithmParams) "do not try and enrich algorithm params";
]

let getopt_params = {
  default_progname = "x509show";
  options = options;
  postprocess_funs = [];
}


let pretty_print_certificate cert =
  let tbs = cert.tbsCertificate in
  if tbs.signature <> cert.signatureAlgorithm
  then ();  (* TODO *)
  [
    (match tbs.version with
    | None -> "Version: no version given"
    | Some v -> Printf.sprintf "Version: %d" v);

    Printf.sprintf "Signature: %s " (string_of_oid tbs.signature.algorithmId); (* TODO: Params *)
    Printf.sprintf "Issuer: %s " (string_of_distinguishedName tbs.issuer);
    "Validity";
    Printf.sprintf "    Not before: %s" (string_of_time tbs.validity.notBefore);
    Printf.sprintf "    Not after: %s" (string_of_time tbs.validity.notAfter);
    Printf.sprintf "Subject: %s" (string_of_distinguishedName tbs.subject);
  ]@
    (Str.split (Str.regexp_string "\n") (print_subjectPublicKeyInfo
			                   tbs.subjectPublicKeyInfo))
  @[
  ]

let handle_input input =
  lwt_parse_certificate input >>= fun certificate ->
  let display = match !action with
    | Serial -> [hexdump certificate.tbsCertificate.serialNumber]
    | CheckSelfSigned ->
      let result = match certificate.tbsCertificate_raw,
	certificate.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey,
	certificate.signatureValue
	with
	| m, RSA {p_modulus = n; p_publicExponent = e}, RSASignature (0, s) ->
	  (try Pkcs1.raw_verify 1 m s n e with Pkcs1.PaddingError -> false)
	| _ -> false
      in [string_of_bool (result)]
    | Subject -> ["[" ^ String.concat ", " (List.map string_of_atv (List.flatten certificate.tbsCertificate.subject)) ^ "]"]
    | Issuer -> ["[" ^ String.concat ", " (List.map string_of_atv (List.flatten certificate.tbsCertificate.issuer)) ^ "]"]
    | Modulus ->
      let result = match certificate.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey with
	| RSA {p_modulus = n} -> hexdump n
	| _ -> "No RSA modulus found or parsed"
      in [result]
    | BinDump -> [dump_certificate certificate]
    | Dump -> [hexdump (dump_certificate certificate)]
    | Text -> Str.split (Str.regexp_string "\n") (print_certificate certificate)
    | PrettyPrint -> pretty_print_certificate certificate
  in
  match !print_names with
    | Default -> lwt_not_implemented "handle_input can not determine wether filenames should be printed"
    | PrintName ->
      let print_line l = Printf.printf "%s:%s\n" input.lwt_name l in
      List.iter print_line display;
      return ()
    | DoNotPrintName ->
      List.iter print_endline display;
      return ()


let catch_exceptions e =
  if !keep_going
  then begin
    prerr_endline (Printexc.to_string e);
    return ()
  end else fail e

let rec iter_on_names = function
  | [] -> return ()
  | f::r ->
    let t = input_of_filename f >>= handle_input in
    catch (fun () -> t) catch_exceptions >>= fun () ->
    iter_on_names r



let _ =
  let args = parse_args getopt_params Sys.argv in
  let t = match args with
    | [] ->
      if !print_names = Default then print_names := DoNotPrintName;
      input_of_channel "(stdin)" Lwt_io.stdin >>= handle_input
    | [a] ->
      if !print_names = Default then print_names := DoNotPrintName;
      iter_on_names args
    | _ ->
      if !print_names = Default then print_names := PrintName;
      iter_on_names args
  in
  try
    Lwt_unix.run t;
    exit 0
  with
    | ParsingException (e, h) -> prerr_endline (string_of_exception e h); exit 1
    | e -> prerr_endline (Printexc.to_string e); exit 1
