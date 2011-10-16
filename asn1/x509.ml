open Asn1
open Asn1Constraints
open Asn1.Asn1EngineParams
open Asn1.Engine

type oid_type =
  | HashAlgo
  | SigAlgo
  | PubKeyAlgo
  | ATV
  | Extension

type preparse_function = parsing_state -> parsing_state
type predump_function = parsing_state -> parsing_state

let (name_directory : (int list, string) Hashtbl.t) = Hashtbl.create 100
let (object_directory : ((oid_type * int list),
			 (asn1_object asn1_constraint * severity)) Hashtbl.t) = Hashtbl.create 50
let (initial_directory : (int list, string) Hashtbl.t) = Hashtbl.create 50
let (pubkey_directory : (int list, asn1_object asn1_constraint) Hashtbl.t) = Hashtbl.create 10
let (signature_directory : (int list, (asn1_object asn1_constraint *
					 preparse_function * predump_function)) Hashtbl.t) = Hashtbl.create 10


(* Generic code about objects (OId + ASN1_Object depending on the OId) *)

type oid_object = {
  oo_id : int list;
  oo_content : asn1_object option
}

let empty_oid_object = { oo_id = []; oo_content = None }


let parse_oid_object dir oid_type oid_sev pstate =
  let oid = constrained_parse_def oid_cons oid_sev [] pstate in
  let content_cons, content_sev = if Hashtbl.mem dir (oid_type, oid)
    then Hashtbl.find dir (oid_type, oid)
    else (Anything Common.identity), S_Benign
  in
  let content = match common_constrained_parse content_cons pstate with
    | Left (TooFewObjects _) -> None
    | Left err ->
      emit err content_sev pstate;
      (* We try to get anything is the severity was not too much *)
      constrained_parse_opt (Anything Common.identity) S_OK pstate
    | Right o -> Some o
  in
  if not (eos pstate)
  then emit (TooManyObjects None) S_SpecLightlyViolated pstate;
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
	oid_string ^ "Parameters:\n" ^ (string_of_object new_indent opts p)
  end


(* Version *)

let extract_version l =
  try
    match l with
      | [[i]] -> i + 1
      | _ -> 0
  with
      Failure "int_of_big_int" -> 0

let version_constraint : int asn1_constraint =
  Simple_cons (C_ContextSpecific, true, 0, "Version",
	       parse_sequenceof extract_version int_cons (Exactly (1, S_SpecFatallyViolated)))




(* Serial *)
let serial_constraint = int_cons


(* Signature algo *)

let sigalgo_constraint dir : oid_object asn1_constraint =
  object_constraint dir SigAlgo S_SpecFatallyViolated "Signature Algorithm"


(* Distinguished names *)

type atv = oid_object
type rdn = atv list
type dn = rdn list

let atv_constraint dir : atv asn1_constraint =
  object_constraint dir ATV S_SpecFatallyViolated "ATV"
let rdn_constraint dir : rdn asn1_constraint =
  setOf_cons Common.identity "Relative DN" (atv_constraint dir) (AtLeast (1, S_SpecFatallyViolated))
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
  hour : int; minute : int; second : int
}

type datetime =
  | InvalidDateTime
  | DateTime of datetime_content


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
  if n < expected_len then InvalidDateTime else begin
    let year = year_of_string () in
    let month = Common.pop_int s year_len 2 in
    let day = Common.pop_int s (2 + year_len) 2 in
    let hour = Common.pop_int s (4 + year_len) 2 in
    let minute = Common.pop_int s (6 + year_len) 2 in
    match year, month, day, hour, minute with
      | Some y, Some m, Some d, Some hh, Some mm ->
	let ss = if (n < expected_len + 2)
	  then 0
	  else begin 
	    match (Common.pop_int s (8 + year_len) 2) with
	      | None -> 0
	      | Some seconds -> seconds
	  end
	in DateTime { year = y; month = m; day = d;
		      hour = hh; minute = mm; second = ss }
      | _ -> InvalidDateTime
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

let empty_validity = { not_before = InvalidDateTime; not_after = InvalidDateTime }

let extract_validity = function
  | [nb; na] -> { not_before = nb; not_after = na }
  | _ -> { not_before = InvalidDateTime; not_after = InvalidDateTime }

let validity_constraint : validity asn1_constraint =
  seqOf_cons extract_validity "Validity" datetime_constraint (Exactly (2, S_SpecFatallyViolated))


let string_of_datetime = function
  | InvalidDateTime -> "Invalid date/time"
  | DateTime dt ->
    Printf.sprintf "%4.4d-%2.2d-%2.2d %2.2d:%2.2d:%2.2d"
      dt.year dt.month dt.day dt.hour dt.minute dt.second

let string_of_validity indent _ v =
  indent ^ "Not before: " ^ (string_of_datetime v.not_before) ^ "\n" ^
  indent ^ "Not after: " ^ (string_of_datetime v.not_after) ^ "\n"



(* Public key *)

type public_key =
  | PK_WrongPKInfo
  | PK_Unparsed of string

type public_key_info = {
  pk_algo : oid_object;
  public_key : public_key;
}

let empty_public_key_info = { pk_algo = empty_oid_object; public_key = PK_WrongPKInfo }

let extract_public_key_info = function
  | Some algo, Some (0, pk) -> { pk_algo = algo; public_key = PK_Unparsed pk }
  | Some algo, _ -> { pk_algo = algo; public_key = PK_WrongPKInfo }
  | _ -> empty_public_key_info

let pubkeyalgo_constraint dir : oid_object asn1_constraint =
  object_constraint dir PubKeyAlgo S_SpecFatallyViolated "Public Key Algorithm"

let public_key_info_constraint dir : public_key_info asn1_constraint =
  custom_pair_cons C_Universal 16 "Public Key Info" extract_public_key_info
    (pubkeyalgo_constraint dir) bitstring_cons S_SpecFatallyViolated


let string_of_public_key_info indent resolver pki =
  let new_indent = indent ^ "  " in
  indent ^ "Public key algorithm:\n" ^ (string_of_oid_object new_indent resolver pki.pk_algo) ^
    (match pki.public_key with
      | PK_WrongPKInfo -> "Wrong PK Info\n"
      | PK_Unparsed s -> Common.hexdump (s) ^ "\n")



(* TBS Certificate *)

type tbs_certificate = {
  version : int option;
  serial : int list;
  sig_algo : oid_object;
  issuer : dn;
  validity : validity;
  subject : dn;
  pk_info : public_key_info;
  issuer_unique_id : (int * string) option;
  subject_unique_id : (int * string) option;
  (* TODO *)
  extensions : asn1_object option
}

let empty_tbs_certificate =
  { version = None; serial = []; sig_algo = empty_oid_object;
    issuer = []; validity = empty_validity; subject = [];
    pk_info = empty_public_key_info; issuer_unique_id = None;
    subject_unique_id = None; extensions = None }

let parse_tbs_certificate dir pstate =
  let version = constrained_parse_opt version_constraint S_OK pstate in
  let serial = constrained_parse_def serial_constraint S_SpecFatallyViolated [] pstate in
  let sig_algo = constrained_parse_def (sigalgo_constraint dir) S_SpecFatallyViolated empty_oid_object pstate in
  let issuer = constrained_parse_def (dn_constraint dir "Issuer") S_SpecFatallyViolated [] pstate in
  let validity = constrained_parse_def validity_constraint S_SpecFatallyViolated empty_validity pstate in
  let subject = constrained_parse_def (dn_constraint dir "Subject") S_SpecFatallyViolated [] pstate in
  let pk_info = constrained_parse_def (public_key_info_constraint dir) S_SpecFatallyViolated empty_public_key_info pstate in

  let issuer_unique_id =
      constrained_parse_opt (Simple_cons (C_ContextSpecific, false, 1, "Issuer Unique Identifer",
					  raw_der_to_bitstring 54)) S_OK pstate in

  let subject_unique_id =
    constrained_parse_opt (Simple_cons (C_ContextSpecific, false, 2, "Subject Unique Identifer",
					raw_der_to_bitstring 54)) S_OK pstate in


  (* TODO *)
  let extensions =
    constrained_parse_opt (Simple_cons (C_ContextSpecific, true, 3, "Extensions container",
					parse_sequenceof List.hd (Anything Common.identity)
					  (Exactly (1, S_SpecLightlyViolated))))
      S_OK pstate in


  let effective_version = match version with
    | None -> 1
    | Some x -> x
  in

  begin
    match effective_version, issuer_unique_id, subject_unique_id with
      | _, None, None -> ()
      | v, _, _ ->
	if v < 2 then emit (UnexpectedObject "unique id") S_SpecLightlyViolated pstate
  end;

  begin
    match effective_version, extensions with
      | _, None -> ()
      | v, _ ->
	if v < 3 then emit (UnexpectedObject "extension") S_SpecLightlyViolated pstate
  end;

  if not (eos pstate) then emit (TooManyObjects None) S_SpecLightlyViolated pstate;

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
    indent ^ "Serial: " ^ (Common.hexdump_int_list tbs.serial) ^ "\n" ^
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
	(* TODO *)
	let opts = { type_repr = PrettyType; data_repr = PrettyData;
		     resolver = resolver; indent_output = true } in
	indent ^ "Extensions:\n" ^ (string_of_object new_indent opts e))


(* Certificate *)
 
type certificate = {
  tbs : tbs_certificate;
  cert_sig_algo : oid_object;
  signature : (int * string)
}


let parse_certificate dir pstate =
  let tbs = constrained_parse_def (tbs_certificate_constraint dir) S_SpecFatallyViolated empty_tbs_certificate pstate in
  let sig_algo = constrained_parse_def (sigalgo_constraint dir) S_SpecFatallyViolated empty_oid_object pstate in
  let signature = constrained_parse_def (Simple_cons (C_Universal, false, 3, "Signature",
					raw_der_to_bitstring 54)) S_OK (0, "") pstate in

  { tbs = tbs; cert_sig_algo = sig_algo; signature = signature }


let certificate_constraint dir : certificate asn1_constraint =
  Simple_cons (C_Universal, true, 16, "Certificate", parse_certificate dir)


let rec string_of_certificate print_title indent resolver c =
  let new_indent = indent ^ "  " in
  if (print_title)
  then indent ^ "Certificate:\n" ^ (string_of_certificate false new_indent resolver c)
  else indent ^ "tbsCertificate:\n" ^ (string_of_tbs_certificate new_indent resolver c.tbs) ^
    indent ^ "Signature algorithm:\n" ^ (string_of_oid_object new_indent resolver c.cert_sig_algo) ^
    indent ^ "Signature: " ^ (string_of_bitstring false (fst c.signature) (snd c.signature)) ^
    "\n"
		 




(*

let pkcs1_RSA_private_key = seqOf_cons mk_object "RSA Private Key" int_cons (Exactly (9, S_SpecFatallyViolated))
let pkcs1_RSA_public_key = seqOf_cons mk_object "RSA Public Key" int_cons (Exactly (2, S_SpecFatallyViolated))

*)
