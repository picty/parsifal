open Common
open Types
open Modules
open Printer
open ParsingEngine
open Asn1
open Asn1Constraints

open X509Misc
open X509DN
open X509Validity
open X509PublicKey
open X509Extensions
open X509Signature

open X509RSA


(* TBS Certificate *)

type tbs_certificate = {
  version : int option;
  serial : string;
  sig_algo : oid_object;
  issuer : dn;
  validity : validity;
  subject : dn;
  pk_info : public_key_info;
  issuer_unique_id : (int * string) option;
  subject_unique_id : (int * string) option;
  extensions : extension list option;
}

let empty_tbs_certificate =
  { version = None; serial = ""; sig_algo = empty_oid_object;
    issuer = []; validity = empty_validity; subject = [];
    pk_info = empty_public_key_info; issuer_unique_id = None;
    subject_unique_id = None; extensions = None }

let parse_tbs_certificate pstate =
  let version = constrained_parse_opt version_constraint s_ok pstate in
  let serial = constrained_parse_def serial_constraint s_specfatallyviolated "" pstate in
  let sig_algo = constrained_parse_def (sigalgo_constraint) s_specfatallyviolated empty_oid_object pstate in
  let issuer = constrained_parse_def (dn_constraint "Issuer") s_specfatallyviolated [] pstate in
  let validity = constrained_parse_def validity_constraint s_specfatallyviolated empty_validity pstate in
  let subject = constrained_parse_def (dn_constraint "Subject") s_specfatallyviolated [] pstate in
  let pk_info = constrained_parse_def (public_key_info_constraint) s_specfatallyviolated empty_public_key_info pstate in

  let issuer_unique_id =
      constrained_parse_opt (Simple_cons (C_ContextSpecific, false, 1, "Issuer Unique Identifer",
					  raw_der_to_bitstring)) s_ok pstate in

  let subject_unique_id =
    constrained_parse_opt (Simple_cons (C_ContextSpecific, false, 2, "Subject Unique Identifer",
					raw_der_to_bitstring)) s_ok pstate in

  let extensions =
    constrained_parse_opt (Simple_cons (C_ContextSpecific, true, 3, "Extensions container",
					parse_sequenceof List.hd (extensions_constraint pstate.ehf)
					  (Exactly (1, s_speclightlyviolated)))) s_ok pstate in

  let effective_version = match version with
    | None -> 1
    | Some x -> x
  in

  begin
    match effective_version, issuer_unique_id, subject_unique_id with
      | _, None, None -> ()
      | v, _, _ ->
	if v < 2 then asn1_emit UnexpectedUniqueIdentifier None None pstate
  end;

  begin
    match effective_version, extensions with
      | _, None -> ()
      | v, _ ->
	if v < 3 then asn1_emit UnexpectedExtension None None pstate
  end;

  if not (eos pstate) then asn1_emit TooManyObjects None None pstate;

  { version = version; serial = serial; sig_algo = sig_algo;
    issuer = issuer; validity = validity; subject = subject;
    pk_info = pk_info; issuer_unique_id = issuer_unique_id;
    subject_unique_id = subject_unique_id; extensions = extensions }

let tbs_certificate_constraint : tbs_certificate asn1_constraint =
  Simple_cons (C_Universal, true, 16, "tbsCertificate", parse_tbs_certificate)


let string_of_tbs_certificate title tbs =
  let version_str = match tbs.version with
    | None -> []
    | Some i -> ["Version: " ^ (string_of_int i)]
  in
  let serial_str = ["Serial: " ^ (hexdump tbs.serial)] in
  let sigalgo_str = string_of_oid_object (Some "Signature algorithm") tbs.sig_algo in
  let issuer_str = string_of_dn (Some "Issuer") tbs.issuer in
  let validity_str = PrinterLib._string_of_strlist (Some "Validity") indent_only (string_of_validity tbs.validity) in
  let subject_str = string_of_dn (Some "Subject") tbs.subject in
  let pki_str = string_of_public_key_info tbs.pk_info in
  let issuer_uid_str = match tbs.issuer_unique_id with
    | None -> []
    | Some (nb, s) -> [PrinterLib._single_line (Some "Issuer Unique Identifier") (string_of_bitstring false nb s)]
  and subject_uid_str = match tbs.subject_unique_id with
    | None -> []
    | Some (nb, s) -> [PrinterLib._single_line (Some "Subject Unique Identifier") (string_of_bitstring false nb s)]
  and extensions_str = match tbs.extensions with
    | None -> []
    | Some e ->
      let exts_strlist = List.flatten (List.map string_of_extension e) in
      PrinterLib._string_of_strlist (Some "Extensions") indent_only exts_strlist
  in
  let tbs_str = List.flatten [version_str; serial_str; sigalgo_str; issuer_str;
			      validity_str; subject_str; pki_str; issuer_uid_str;
			      subject_uid_str; extensions_str] in
  PrinterLib._string_of_strlist title indent_only tbs_str




module Tbs = struct
  type t = tbs_certificate
  let name = "tbs"
  let params = []

  let parse = constrained_parse tbs_certificate_constraint
  let dump tbs = raise (NotImplemented "tbs.dump")

  let enrich tbs dict =
    let handle_unique_id id_name = function
      | None -> ()
      | Some (n, s) -> Hashtbl.replace  dict id_name (V_BitString (n, s))
    in

    begin
      match tbs.version with
	| None -> ()
	| Some v -> Hashtbl.replace dict "version" (V_Int v)
    end;
    Hashtbl.replace dict "serial" (V_Bigint tbs.serial);
    Hashtbl.replace dict "signature_algorithm" (OIdObjectModule.register tbs.sig_algo);
    Hashtbl.replace dict "issuer" (DNModule.register tbs.issuer);
    Hashtbl.replace dict "validity" (ValidityModule.register tbs.validity);
    Hashtbl.replace dict "subject" (DNModule.register tbs.subject);
    Hashtbl.replace dict "public_key_info" (PublicKeyInfoModule.register tbs.pk_info);

    handle_unique_id "issuer_unique_id" tbs.issuer_unique_id;
    handle_unique_id "subject_unique_id" tbs.subject_unique_id;
    begin
      match tbs.extensions with
	| None -> ()
	| Some exts ->
	  Hashtbl.replace dict "extensions" (V_List (List.map ExtensionModule.register exts))
    end;
    ()

  let update dict = raise (NotImplemented "tbs.update")
  let to_string = string_of_tbs_certificate (Some "TBS")
  let functions = []
end

module TbsModule = MakeParserModule (Tbs)
let _ = add_object_module ((module TbsModule : ObjectModule))




(* Certificate *)
 
type certificate = {
  tbs : tbs_certificate;
  cert_sig_algo : oid_object;
  signature : signature
}


let parse_certificate pstate =
  let tbs = constrained_parse_def tbs_certificate_constraint s_specfatallyviolated empty_tbs_certificate pstate in
  let sig_algo = constrained_parse_def sigalgo_constraint s_specfatallyviolated empty_oid_object pstate in
  let signature = constrained_parse_def (signature_constraint sig_algo) s_specfatallyviolated empty_signature pstate in
  { tbs = tbs; cert_sig_algo = sig_algo; signature = signature }


let certificate_constraint : certificate asn1_constraint =
  Simple_cons (C_Universal, true, 16, "Certificate", parse_certificate)


(* TODO *)
let rec string_of_certificate title cert =
  let cert_str = List.flatten [
    string_of_tbs_certificate (Some "tbsCertificate") cert.tbs;
    string_of_oid_object (Some "Signature algorithm") cert.cert_sig_algo;
    string_of_signature (Some "Signature") cert.signature
  ] in
  PrinterLib._string_of_strlist title indent_only cert_str

let rec _get_extension exts oid = match exts with
  | [] -> V_Unit
  | e::r ->
    if e.e_id = oid
    then ExtensionModule.register e
    else _get_extension r oid

let rec _get_content_extension exts oid = match exts with
  | [] -> V_Unit
  | e::r ->
    if e.e_id = oid
    then e.e_content
    else _get_content_extension r oid

let get_extension exts_container ext_id =
  match exts_container with
    | None -> V_Unit
    | Some exts ->
      let oid = match ext_id with
	| V_List oid -> Asn1Parser.oid_of_list oid
	| V_String s -> begin
	  try Hashtbl.find rev_name_directory s
	  with Not_found -> begin
	    try oid_squash (List.map int_of_string (string_split '.' s))
	    with Failure "int_of_string" -> raise (ContentError ("Unknown OId"))
	  end
	end
	| _ -> raise (ContentError ("OId must be strings or int list"))
      in _get_extension exts oid


let test_usage ext_id test_fun cert =
  match _get_content_extension (pop_option cert.tbs.extensions []) ext_id with
    | V_List usages -> Some (test_fun (List.map eval_as_string usages))
    | V_Unit -> None
    | _ -> Some false

let rec multimem pattern = function
  | [] -> false
  | x::r -> List.mem x pattern || multimem pattern r

let raw_has_key_usage usage cert = test_usage keyUsage_oid (List.mem usage) cert
let raw_has_cert_type cert_type cert = test_usage nsCertType_oid (List.mem cert_type) cert
let raw_has_one_of_key_usages usages cert = test_usage keyUsage_oid (multimem usages) cert
let raw_has_one_of_cert_types types cert = test_usage nsCertType_oid (multimem types) cert


let raw_is_ca cert =
  match _get_content_extension (pop_option cert.tbs.extensions []) basicConstraints_oid with
    | V_Dict bc -> Some (eval_as_bool (hash_find_default bc "CA" (V_Bool false)))
    | _ -> None


let lift_test_ext f cert def_if_not_v3 def_if_ext_absent =
  match cert.tbs.version with
    | None | Some 1 | Some 2 -> V_Bool def_if_not_v3
    | Some _ ->
      match f cert with
	| None -> V_Bool def_if_ext_absent
	| Some b -> V_Bool b

type blurry_result =
  | Yes
  | MostlyYes
  | MostlyNo
  | No


let is_ca cert =
  match cert.tbs.version with
    | None | Some 1 | Some 2 -> Yes
    | Some _ ->
      match raw_is_ca cert, raw_has_key_usage "keyCertSign" cert,
	raw_has_one_of_cert_types ["sslCA"; "emailCA"; "objCA"] cert with
	  | Some true, (Some true | None), (Some true | None) -> Yes
	  | Some true, _, _ -> MostlyYes
	  | Some false, (Some false | None), (Some false | None) -> No
	  | Some false, _, _ -> MostlyNo
	  | None, (Some false | None), (Some false | None) -> No
	  | None, (Some true | None), (Some true | None) -> MostlyYes
	  | None, Some _, Some _ -> MostlyNo

let string_of_blurry = function
  | Yes -> V_String "Yes"
  | MostlyYes -> V_String "MostlyYes"
  | MostlyNo -> V_String "MostlyNo"
  | No -> V_String "No"


module X509 = struct
  type t = certificate
  let name = "x509"
  let params = [
    param_from_bool_ref "parse_public_key" parse_public_key;
    param_from_bool_ref "parse_extensions" parse_extensions;
    param_from_bool_ref "parse_signature" parse_signature;
  ]

  let parse = constrained_parse certificate_constraint
  let dump cert = raise (NotImplemented "x509.dump")

  let enrich cert dict =
    Hashtbl.replace dict "tbs" (TbsModule.register cert.tbs);
    Hashtbl.replace dict "signature_algorithm" (OIdObjectModule.register cert.cert_sig_algo);
    Hashtbl.replace dict "signature" cert.signature;
    begin
      match cert.tbs.version with
	| None -> Hashtbl.replace dict "effective_version" (V_Int 1)
	| Some v -> Hashtbl.replace dict "effective_version" (V_Int v)
    end;
    Hashtbl.replace dict "get_extension" (one_value_fun (get_extension cert.tbs.extensions));
    Hashtbl.replace dict "is_ca" (zero_value_fun (fun () -> string_of_blurry (is_ca cert)));
    begin
      match cert.tbs.pk_info.public_key with
	| V_BitString _ -> ()
	| v -> Hashtbl.replace dict "public_key" v
    end

  let update dict = raise (NotImplemented "x509.update")

  let to_string = string_of_certificate (Some "Certificate")
  let functions = []
end

module X509Module = MakeParserModule (X509)
let _ = add_object_module ((module X509Module : ObjectModule))
