open Types
open Modules
open NewParsingEngine
open Asn1Constraints



(* OId Objects (OId + ASN1_Object depending on the OId) *)

type oid_type =
  | HashAlgo
  | SigAlgo
  | PubKeyAlgo
  | ATV
  | Extension

let (object_directory : ((oid_type * int list),
			 (asn1_object asn1_constraint * severity)) Hashtbl.t) = Hashtbl.create 50


type oid_object = {
  oo_id : int list;
  oo_content : asn1_object option
}

let empty_oid_object = { oo_id = []; oo_content = None }


let parse_oid_object dir oid_type oid_sev pstate =
  let oid = constrained_parse_def oid_cons oid_sev [] pstate in
  let content_cons, content_sev = if Hashtbl.mem dir (oid_type, oid)
    then Hashtbl.find dir (oid_type, oid)
    else (Anything Common.identity), s_benign
  in
  let content = match common_constrained_parse content_cons pstate with
    | Left (TooFewObjects _) -> None
    | Left err ->
      emit err content_sev pstate;
      (* We try to get anything is the severity was not too much *)
      constrained_parse_opt (Anything Common.identity) s_ok pstate
    | Right o -> Some o
  in
  if not (eos pstate)
  then emit (TooManyObjects None) s_speclightlyviolated pstate;
  { oo_id = oid; oo_content = content }


let object_constraint dir oid_type oid_sev name =
  Simple_cons (C_Universal, true, 16, name, parse_oid_object dir oid_type oid_sev)


let string_of_oid_object indent resolver o =
  let oid_string = indent ^ (string_of_oid resolver o.oo_id) ^ "\n" in
  begin
    match o.oo_content with
      | None
      | Some {a_content = Null} -> oid_string
      | Some p ->
	(* TODO *)
	let opts = { type_repr = PrettyType; data_repr = PrettyData;
		     resolver = resolver; indent_output = true } in
	let new_indent = indent ^ "  " in
	oid_string ^ indent ^ "Parameters:\n" ^ (string_of_object new_indent opts p)
  end

(*


open ParsingEngine
open Asn1
open Asn1Constraints



let (name_directory : (int list, string) Hashtbl.t) = Hashtbl.create 100
let (initial_directory : (int list, string) Hashtbl.t) = Hashtbl.create 50




(* Version *)

let extract_version l =
  match l with
    | [s] ->
      if String.length s = 1
      then int_of_char (s.[0]) + 1
      else 0
    | _ -> 0

let version_constraint : int asn1_constraint =
  Simple_cons (C_ContextSpecific, true, 0, "Version",
	       parse_sequenceof extract_version int_cons (Exactly (1, s_specfatallyviolated)))




(* Serial *)
let serial_constraint = int_cons


(* Signature algo *)

let sigalgo_constraint dir : oid_object asn1_constraint =
  object_constraint dir SigAlgo s_specfatallyviolated "Signature Algorithm"


(* Distinguished names *)

type atv = oid_object
type rdn = atv list
type dn = rdn list

let atv_constraint dir : atv asn1_constraint =
  object_constraint dir ATV s_specfatallyviolated "ATV"
let rdn_constraint dir : rdn asn1_constraint =
  setOf_cons Common.identity "Relative DN" (atv_constraint dir) (AtLeast (1, s_specfatallyviolated))
let dn_constraint dir name : dn asn1_constraint =
  seqOf_cons Common.identity name (rdn_constraint dir) AlwaysOK

let string_of_atv indent resolver atv =
  let atv_opts = { type_repr = NoType; data_repr = PrettyData;
		   resolver = resolver; indent_output = false } in
  indent ^ (string_of_oid resolver atv.oo_id) ^
    (match atv.oo_content with
      | None -> ""
      | Some o ->
	 ": " ^ (string_of_object "" atv_opts o)
    ) ^ "\n"

let string_of_rdn indent resolver rdn =
  String.concat "" (List.map (string_of_atv indent resolver) rdn)

let string_of_dn indent resolver dn =
  String.concat "" (List.map (string_of_rdn indent resolver) dn)


(* Time and validity *)

type datetime_content = {
  year : int; month : int; day : int;
  hour : int; minute : int; second : int option
}

type datetime = datetime_content option

let pop_datetime four_digit_year pstate =
  let s = pop_string pstate in

  let year_of_string () =
    if four_digit_year
    then Common.pop_int s 0 4
    else begin
      match Common.pop_int s 0 2 with
	| None -> None
	| Some x -> Some ((if x < 50 then 2000 else 1900) + x)
    end
  in

  let year_len = if four_digit_year then 4 else 2 in
  let expected_len = year_len + 8 in
  let n = String.length s in
  if n < expected_len then None else begin
    let year = year_of_string () in
    let month = Common.pop_int s year_len 2 in
    let day = Common.pop_int s (2 + year_len) 2 in
    let hour = Common.pop_int s (4 + year_len) 2 in
    let minute = Common.pop_int s (6 + year_len) 2 in
    match year, month, day, hour, minute with
      | Some y, Some m, Some d, Some hh, Some mm ->
	let ss = if (n < expected_len + 2)
	  then None
	  else Common.pop_int s (8 + year_len) 2
	in Some { year = y; month = m; day = d;
		  hour = hh; minute = mm; second = ss }
      | _ -> None
  (* TODO: Handle trailing bytes? *)
  end

let datetime_constraint : datetime asn1_constraint =
  let aux c isC t =
    if c = C_Universal && not isC then begin
      match t with
	| 23 -> Some ("Time", pop_datetime false)
	| 24 -> Some ("Time", pop_datetime true)
	| _ -> None
    end else None
  in Complex_cons aux


type validity = { not_before : datetime; not_after : datetime }

let empty_validity = { not_before = None; not_after = None }

let extract_validity = function
  | [nb; na] -> { not_before = nb; not_after = na }
  | _ -> { not_before = None; not_after = None }

let validity_constraint : validity asn1_constraint =
  seqOf_cons extract_validity "Validity" datetime_constraint (Exactly (2, s_specfatallyviolated))


let string_of_datetime = function
  | None -> "Invalid date/time"
  | Some dt ->
    Printf.sprintf "%4.4d-%2.2d-%2.2d %2.2d:%2.2d:%2.2d"
      dt.year dt.month dt.day dt.hour dt.minute (Common.pop_option dt.second 0)

let string_of_validity indent _ v =
  indent ^ "Not before: " ^ (string_of_datetime v.not_before) ^ "\n" ^
  indent ^ "Not after: " ^ (string_of_datetime v.not_after) ^ "\n"



(* Public key *)

type dsa_public_key = {dsa_p : string; dsa_q : string; dsa_g : string; dsa_Y : string}
type rsa_public_key = {rsa_n : string; rsa_e : string}

type public_key =
  | PK_WrongPKInfo
  | PK_DSA of dsa_public_key
  | PK_RSA of rsa_public_key
  | PK_Unparsed of string

type pk_parse_fun = asn1_object option -> string -> public_key
let (pubkey_directory : (int list, pk_parse_fun) Hashtbl.t) = Hashtbl.create 10

type public_key_info = {
  pk_algo : oid_object;
  public_key : public_key;
}

let empty_public_key_info = { pk_algo = empty_oid_object; public_key = PK_WrongPKInfo }

let extract_public_key_info = function
  | Some algo, Some (0, pk) -> begin
    try
      (* TODO: This should be optional *)
      let extract_aux = Hashtbl.find pubkey_directory algo.oo_id in
      { pk_algo = algo; public_key = extract_aux algo.oo_content pk}
    with Not_found -> { pk_algo = algo; public_key = PK_Unparsed pk }
  end
  | Some algo, _ -> { pk_algo = algo; public_key = PK_WrongPKInfo }
  | _ -> empty_public_key_info

let pubkeyalgo_constraint dir : oid_object asn1_constraint =
  object_constraint dir PubKeyAlgo s_specfatallyviolated "Public Key Algorithm"

let public_key_info_constraint dir : public_key_info asn1_constraint =
  custom_pair_cons C_Universal 16 "Public Key Info" extract_public_key_info
    (pubkeyalgo_constraint dir) bitstring_cons s_specfatallyviolated


let string_of_public_key_info indent resolver pki =
  let new_indent = indent ^ "  " in
    (match pki.public_key with
      | PK_WrongPKInfo ->
	indent ^ "Wrong Public Key Info:\n" ^
	  new_indent ^ "Public key algorithm:\n" ^ (string_of_oid_object new_indent resolver pki.pk_algo)
      | PK_DSA {dsa_p; dsa_q; dsa_g; dsa_Y} ->
	indent ^ "DSA Public Key:\n" ^
	  new_indent ^ "p: 0x" ^ (Common.hexdump dsa_p) ^ "\n" ^
	  new_indent ^ "q: 0x" ^ (Common.hexdump dsa_q) ^ "\n" ^
	  new_indent ^ "g: 0x" ^ (Common.hexdump dsa_g) ^ "\n" ^
	  new_indent ^ "Y: 0x" ^ (Common.hexdump dsa_Y) ^ "\n"
      | PK_RSA {rsa_n; rsa_e} ->
	indent ^ "RSA Public Key:\n" ^
	  new_indent ^ "n: 0x" ^ (Common.hexdump rsa_n) ^ "\n" ^
	  new_indent ^ "e: 0x" ^ (Common.hexdump rsa_e) ^ "\n"
      | PK_Unparsed s ->
	indent ^ "Public key:\n" ^
	  new_indent ^ "Public key algorithm:\n" ^ (string_of_oid_object new_indent resolver pki.pk_algo) ^
	  new_indent ^ "Value: [HEX]" ^ Common.hexdump (s) ^ "\n")


(* Extensions *)
type aki =
  | AKI_KeyIdentifier of string
  | AKI_Unknown

type ext_content =
  | BasicConstraints of (bool option * string option)
  | SubjectKeyIdentifier of string
  | AuthorityKeyIdentifier of aki (* Not fully compliant *)
  | CRLDistributionPoint of string (* Only partial implementation *)
  | AuthorityInfoAccess_OCSP of string (* Only OCSP is supported for now *)
  | KeyUsage of (int * string)
  | ExtKeyUsage of int list list
  | UnparsedExt of (int list * string)
  | InvalidExt

type ext_parse_fun = ext_content asn1_constraint
let (extension_directory : (int list, ext_parse_fun) Hashtbl.t) = Hashtbl.create 15

type extension = { e_critical : bool option; e_content : ext_content }
let empty_extension = { e_critical = None; e_content = InvalidExt }



let extension_content_constraint = {
  severity_if_too_many_objects = s_specfatallyviolated;
  constraint_list = [
    Simple_cons (C_Universal, false, 6, "ExtensionId", der_to_oid), s_specfatallyviolated;
    Simple_cons (C_Universal, false, 1, "Critical", der_to_boolean), s_ok;
    Simple_cons (C_Universal, false, 4, "ExtensionValue", der_to_octetstring true), s_specfatallyviolated
  ]
}

(* TODO: This should be optional *)
let deep_parse_ext id s =
  try
    let ext_cons = Hashtbl.find extension_directory id in
    let pstate = pstate_of_string (string_of_oid None id) s in
    constrained_parse_def ext_cons s_speclightlyviolated (UnparsedExt (id, s)) pstate
  with Not_found -> UnparsedExt (id, s)

let extract_ext = function
  | [OId id; Boolean b; String (s, true)] ->
    { e_critical = Some b; e_content = deep_parse_ext id s }
  | [OId id; String (s, true)] ->
    { e_critical = None; e_content = deep_parse_ext id s }
  | _ -> empty_extension

    
let extension_constraint = Simple_cons (C_Universal, true, 16, "Extension",
					parse_constrained_sequence extract_ext extension_content_constraint)
let extensions_constraint = seqOf_cons Common.identity "Extensions" extension_constraint (AtLeast (1, s_speclightlyviolated))


let string_of_extension indent resolver e =
  let critical_string = match e.e_critical with
    | Some true -> "(critical)"
    | _ -> ""
  in
  let oid_string, content_string = 
    match e.e_content with
      | BasicConstraints (flag, len) ->
	let flag_string = match flag with
	  | None -> []
	  | Some b -> ["CA=" ^ (if b then "true" else "false")]
	in
	let len_string = match len with
	  | None -> []
	  | Some l -> ["PathLen=" ^ (Common.hexdump l)]
	in
	"basicConstraints", String.concat ", " (flag_string@len_string)
      | SubjectKeyIdentifier ski ->
	"subjectKeyIdentifier", Common.hexdump ski
      | AuthorityKeyIdentifier AKI_Unknown ->
	"authorityKeyIdentifier", ""
      | AuthorityKeyIdentifier (AKI_KeyIdentifier aki) ->
	"authorityKeyIdentifier", Common.hexdump aki
      | CRLDistributionPoint s -> "cRLDistributionPoint", s
      | AuthorityInfoAccess_OCSP s -> "authorityInfoAccess", "OCSP " ^ s
      | KeyUsage (i, s) ->
	"keyUsage", "[" ^ (string_of_int i) ^ "]" ^ (Common.hexdump s)
      | ExtKeyUsage l ->
	let new_indent = indent ^ "  " in
	"extendedKeyUsage", "\n" ^ (String.concat "\n" (List.map (fun oid -> new_indent ^ string_of_oid resolver oid) l))
      | UnparsedExt (oid, raw_content) ->
	(string_of_oid resolver oid), "[HEX]" ^ (Common.hexdump raw_content)
      | InvalidExt -> "InvalidExt", ""
  in
  indent ^ oid_string ^ critical_string ^ (if String.length content_string > 0 then ": " else "") ^ content_string ^ "\n"


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
  (* TODO *)
  extensions : extension list option;
}

let empty_tbs_certificate =
  { version = None; serial = ""; sig_algo = empty_oid_object;
    issuer = []; validity = empty_validity; subject = [];
    pk_info = empty_public_key_info; issuer_unique_id = None;
    subject_unique_id = None; extensions = None }

let parse_tbs_certificate dir pstate =
  let version = constrained_parse_opt version_constraint s_ok pstate in
  let serial = constrained_parse_def serial_constraint s_specfatallyviolated "" pstate in
  let sig_algo = constrained_parse_def (sigalgo_constraint dir) s_specfatallyviolated empty_oid_object pstate in
  let issuer = constrained_parse_def (dn_constraint dir "Issuer") s_specfatallyviolated [] pstate in
  let validity = constrained_parse_def validity_constraint s_specfatallyviolated empty_validity pstate in
  let subject = constrained_parse_def (dn_constraint dir "Subject") s_specfatallyviolated [] pstate in
  let pk_info = constrained_parse_def (public_key_info_constraint dir) s_specfatallyviolated empty_public_key_info pstate in

  let issuer_unique_id =
      constrained_parse_opt (Simple_cons (C_ContextSpecific, false, 1, "Issuer Unique Identifer",
					  raw_der_to_bitstring 54)) s_ok pstate in

  let subject_unique_id =
    constrained_parse_opt (Simple_cons (C_ContextSpecific, false, 2, "Subject Unique Identifer",
					raw_der_to_bitstring 54)) s_ok pstate in


  (* TODO *)
  let extensions =
    constrained_parse_opt (Simple_cons (C_ContextSpecific, true, 3, "Extensions container",
					parse_sequenceof List.hd extensions_constraint
					  (Exactly (1, s_speclightlyviolated))))
      s_ok pstate in


  let effective_version = match version with
    | None -> 1
    | Some x -> x
  in

  begin
    match effective_version, issuer_unique_id, subject_unique_id with
      | _, None, None -> ()
      | v, _, _ ->
	if v < 2 then emit (UnexpectedObject "unique id") s_speclightlyviolated pstate
  end;

  begin
    match effective_version, extensions with
      | _, None -> ()
      | v, _ ->
	if v < 3 then emit (UnexpectedObject "extension") s_speclightlyviolated pstate
  end;

  if not (eos pstate) then emit (TooManyObjects None) s_speclightlyviolated pstate;

  { version = version; serial = serial; sig_algo = sig_algo;
    issuer = issuer; validity = validity; subject = subject;
    pk_info = pk_info; issuer_unique_id = issuer_unique_id;
    subject_unique_id = subject_unique_id; extensions = extensions }

let tbs_certificate_constraint dir : tbs_certificate asn1_constraint =
  Simple_cons (C_Universal, true, 16, "tbsCertificate", parse_tbs_certificate dir)


let string_of_tbs_certificate indent resolver tbs =
  let new_indent = indent ^ "  " in
  (match tbs.version with
    | None -> ""
    | Some i -> indent ^ "Version: " ^ (string_of_int i) ^ "\n") ^ 
    indent ^ "Serial: " ^ (Common.hexdump tbs.serial) ^ "\n" ^
    indent ^ "Signature algorithm:\n" ^ (string_of_oid_object new_indent resolver tbs.sig_algo) ^
    indent ^ "Issuer:\n" ^ (string_of_dn new_indent resolver tbs.issuer) ^
    indent ^ "Validity:\n" ^ (string_of_validity new_indent resolver tbs.validity) ^
    indent ^ "Subject:\n" ^ (string_of_dn new_indent resolver tbs.subject) ^
    indent ^ "Public Key Info:\n" ^ (string_of_public_key_info new_indent resolver tbs.pk_info) ^
    (match tbs.issuer_unique_id with
      | None -> ""
      | Some (nb, s) ->
	indent ^ "Issuer Unique Identifier:" ^ indent ^ (string_of_bitstring false nb s) ^ "\n") ^
    (match tbs.subject_unique_id with
      | None -> ""
      | Some (nb, s) ->
  	indent ^ "Subject Unique Identifier:" ^ indent ^ (string_of_bitstring false nb s) ^ "\n") ^
    (match tbs.extensions with
      | None -> ""
      | Some e ->
	indent ^ "Extensions:\n" ^ (String.concat "" (List.map (string_of_extension new_indent resolver) e)))


(* Signature *)

type dsa_signature = {dsa_r : string; dsa_s : string}

type signature =
  | Sig_WrongSignature
  | Sig_DSA of dsa_signature
  | Sig_RSA of string
  | Sig_Unparsed of string

type sig_parse_fun = string -> signature
let (signature_directory : (int list, sig_parse_fun) Hashtbl.t) = Hashtbl.create 10

let empty_signature = Sig_WrongSignature

let extract_signature = function
  | algo, (0, sig_val) -> begin
    try
      (* TODO: This should be optional *)
      let extract_aux = Hashtbl.find signature_directory algo.oo_id in
      extract_aux sig_val
    with Not_found -> Sig_Unparsed sig_val
  end
  | _, _ -> Sig_WrongSignature

let signature_constraint dir sigalgo : signature asn1_constraint =
  Simple_cons (C_Universal, false, 3, "Bit String",
	       fun pstate -> extract_signature (sigalgo, raw_der_to_bitstring "" pstate))


let string_of_signature indent _resolver sign =
  match sign with
    | Sig_WrongSignature -> indent ^ "Wrong Signature\n"
    | Sig_DSA {dsa_r; dsa_s} ->
      indent ^ "r: " ^ (Common.hexdump dsa_r) ^ "\n" ^
	indent ^ "s: " ^ (Common.hexdump dsa_s) ^ "\n"
    | Sig_RSA s ->
      indent ^ "s: " ^ (Common.hexdump s) ^ "\n"
    | Sig_Unparsed s -> indent ^ "[HEX]" ^ (Common.hexdump s) ^ "\n"


(* Certificate *)
 
type certificate = {
  tbs : tbs_certificate;
  cert_sig_algo : oid_object;
  signature : signature
}


let parse_certificate dir pstate =
  let tbs = constrained_parse_def (tbs_certificate_constraint dir) s_specfatallyviolated empty_tbs_certificate pstate in
  let sig_algo = constrained_parse_def (sigalgo_constraint dir) s_specfatallyviolated empty_oid_object pstate in
  let signature = constrained_parse_def (signature_constraint dir sig_algo) s_specfatallyviolated empty_signature pstate in

  { tbs = tbs; cert_sig_algo = sig_algo; signature = signature }


let certificate_constraint dir : certificate asn1_constraint =
  Simple_cons (C_Universal, true, 16, "Certificate", parse_certificate dir)


let rec string_of_certificate print_title indent resolver c =
  let new_indent = indent ^ "  " in
  if (print_title)
  then indent ^ "Certificate:\n" ^ (string_of_certificate false new_indent resolver c)
  else indent ^ "tbsCertificate:\n" ^ (string_of_tbs_certificate new_indent resolver c.tbs) ^
    indent ^ "Signature algorithm:\n" ^ (string_of_oid_object new_indent resolver c.cert_sig_algo) ^
    indent ^ "Signature:\n" ^ (string_of_signature new_indent resolver c.signature) ^
    "\n"
		 




(*

let pkcs1_RSA_private_key = seqOf_cons mk_object "RSA Private Key" int_cons (Exactly (9, s_specfatallyviolated))
let pkcs1_RSA_public_key = seqOf_cons mk_object "RSA Public Key" int_cons (Exactly (2, s_specfatallyviolated))

*)
*)
