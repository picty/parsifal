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
let (object_directory : ((oid_type * int list), (asn1_constraint * severity)) Hashtbl.t) = Hashtbl.create 50
let (initial_directory : (int list, string) Hashtbl.t) = Hashtbl.create 50
let (pubkey_directory : (int list, asn1_constraint) Hashtbl.t) = Hashtbl.create 10
let (signature_directory : (int list, (asn1_constraint * preparse_function * predump_function)) Hashtbl.t) = Hashtbl.create 10

type oid_object = {
  oo_id : int list;
  oo_content : asn1_object option
}


let rec parse_object dir oid_sev pstate =
  let oid = match common_constrained_parse oid_cons pstate with
    | Left err ->
      emit (TooFewObjects None) oid_sev pstate;
      []
    | Right { a_content = OId l } -> l
    | Right _ ->
      emit InternalMayhem S_Fatal pstate;
      []
  in
  let content_cons, content_sev = if Hashtbl.mem dir oid
    then Hashtbl.find dir oid
    else Anything, S_Benign
  in
  let content = match common_constrained_parse content_cons pstate with
    | Left (TooFewObjects _) -> None
    | Left err ->
      emit err content_sev pstate;
      (* We try to get anything is the severity was not too much *)
      constrained_parse_opt Anything pstate
    | Right o -> Some o
  in
  if not (eos pstate)
  then emit (TooManyObjects None) S_SpecLightlyViolated pstate;
  { oo_id = oid; oo_content = content }


(*
(* Distinguished Names *)



type rdn = atv list
type dn = rdn list


let extract_string = function
  | (Asn1.C_Universal, t, Asn1.String s) ->
    if t == 12 || (t >= 18 && t <= 22) || (t >= 25 || t <= 30)
    then s
    else failwith "The value should be string"
  | _ -> failwith "String parameter expected"

let atv_map =
  [ (country_oid, fun o -> Country (extract_string o));
    (locality_oid, fun o -> Locality (extract_string o));
    (state_oid, fun o -> State (extract_string o));
    (organization_oid, fun o -> Organization (extract_string o));
    (organizationalUnit_oid, fun o -> OrganizationalUnit (extract_string o));
    (commonName_oid, fun o -> CommonName (extract_string o));
    (email_oid, fun o -> Email (extract_string o)) ]

let extract_atv objList =
  let oid, arg = match objList with
    | [(Asn1.C_Universal, 6, Asn1.OId oid); o] -> oid, o
    | _ -> failwith "Invalid algorithm identifier"
  in
  try
    (List.assoc oid atv_map) arg
  with
      Not_found -> OtherATV (oid, arg)


(* Extensions *)

type aki =
  | AKI_KeyIdentifier of string
  | AKI_Unknown

type ext_content =
  | BasicConstraints of (bool option * int option)
  | SubjectKeyIdentifier of string
  | AuthorityKeyIdentifier of aki (* Not fully compliant *)
  | CRLDistributionPoint of string (* Only partial implementation *)
  | AuthorityInfoAccess_OCSP of string (* Only OCSP is supported for now *)
  | OtherExt of (int list * string)
  | KeyUsage of (int * string)
  | ExtKeyUsage of int list list
let basicConstraints_oid = [85;29;19]
let subjectKeyIdentifier_oid = [85;29;14]
let authorityKeyIdentifier_oid = [85;29;35]
let crlDistributionPoint_oid = [85;29;31]
let authorityInfoAccess_oid = [43;6;1;5;5;7;1;1]
let keyUsage_oid = [85;29;15]
let extKeyUsage_oid = [85;29;37]
let ocsp_oid = [43;6;1;5;5;7;48;1]

type ext = ext_content * bool option

let mkBasicConstraints s =
  let asn1struct = Asn1.exact_parse s in
  let ca, rem = match asn1struct with
    | (Asn1.C_Universal, 16, Asn1.Constructed 
      ((Asn1.C_Universal, 1, Asn1.Boolean ca)::rem)) -> Some ca, rem
    | (Asn1.C_Universal, 16, Asn1.Constructed rem) -> None, rem
    | _ -> failwith "Invalid basic constraints"
  in
  let pathLenConstraint = match rem with
    | [] -> None
    | [(Asn1.C_Universal, 2, Asn1.Integer i)] -> Some (Big_int.int_of_big_int i)
    | _ -> failwith "Invalid basic constraints"
  in
  BasicConstraints (ca, pathLenConstraint)

let mkSKI s =
  let asn1struct = Asn1.exact_parse s in
  match asn1struct with
    | (Asn1.C_Universal, 4, Asn1.String ki) -> SubjectKeyIdentifier ki
    | _ -> failwith "Invalid subject key identifier"

let mkAKI s =
  let asn1struct = Asn1.exact_parse s in
  match asn1struct with
    | (Asn1.C_Universal, 16, Asn1.Constructed
      [(Asn1.C_ContextSpecific, 0, Asn1.Unknown ki)]) -> AuthorityKeyIdentifier (AKI_KeyIdentifier ki)
    | _ -> AuthorityKeyIdentifier (AKI_Unknown)

let mkCRLDistributionPoint s =
  let asn1struct = Asn1.exact_parse s in
  match asn1struct with
    | (Asn1.C_Universal, 16, Asn1.Constructed
      [(Asn1.C_Universal, 16, Asn1.Constructed
	[(Asn1.C_ContextSpecific, 0, Asn1.Constructed
	  [(Asn1.C_ContextSpecific, 0, Asn1.Constructed
	    [(Asn1.C_ContextSpecific, 6, Asn1.Unknown url)])])])]) -> CRLDistributionPoint url
    | _ -> failwith "Invalid or unknown CRL distribution point"

let mkAuthorityInfoAccess s =
  let asn1struct = Asn1.exact_parse s in
  match asn1struct with
    | (Asn1.C_Universal, 16, Asn1.Constructed
      [(Asn1.C_Universal, 16, Asn1.Constructed
	[(Asn1.C_Universal, 6, Asn1.OId oid);
	 (Asn1.C_ContextSpecific, 6, Asn1.Unknown url)])]) ->
      if oid == ocsp_oid
      then AuthorityInfoAccess_OCSP url
      else failwith "Unknown authority info access extension"
    | _ -> failwith "Invalid or unknown CRL authority info access extension"

let mkKeyUsage s =
  let asn1struct = Asn1.exact_parse s in
  match asn1struct with
    | (Asn1.C_Universal, 3, Asn1.BitString (n, s)) -> KeyUsage (n, s)
    | _ -> failwith "Invalid key usage"

let mkExtKeyUsage s =
  let extractOid = function
    | (Asn1.C_Universal, 6, Asn1.OId oid) -> oid
    | __ -> failwith "OId expected"
  in
  let asn1struct = Asn1.exact_parse s in
  match asn1struct with
    | (Asn1.C_Universal, 16, Asn1.Constructed oidlist) ->
      ExtKeyUsage (List.map extractOid oidlist)
    | _ -> failwith "Invalid extended key usage"


let extension_map =
  [ (basicConstraints_oid, mkBasicConstraints);
    (subjectKeyIdentifier_oid, mkSKI);
    (authorityKeyIdentifier_oid, mkAKI);
    (crlDistributionPoint_oid, mkCRLDistributionPoint);
    (authorityInfoAccess_oid, mkAuthorityInfoAccess);
    (keyUsage_oid, mkKeyUsage);
    (extKeyUsage_oid, mkExtKeyUsage) ]

let extract_extension e = 
  let oid, s, critical = match e with
    | (Asn1.C_Universal, 16, Asn1.Constructed
      [(Asn1.C_Universal, 6, Asn1.OId oid);
       (Asn1.C_Universal, 4, Asn1.String s)])
      -> (oid, s, None)
    | (Asn1.C_Universal, 16, Asn1.Constructed
      [(Asn1.C_Universal, 6, Asn1.OId oid);
       (Asn1.C_Universal, 1, Asn1.Boolean b);
       (Asn1.C_Universal, 4, Asn1.String s)])
      -> (oid, s, Some b)
    | _ -> failwith "Invalid extension"
  in
  try
    ((List.assoc oid extension_map) s, critical)
  with
      Not_found -> (OtherExt (oid, s), critical)



(* type datetime = int * int * int * int * int * int *)
(* TODO *)
type datetime = string
type validity = datetime * datetime

type rsa_pubkey_info = { n : Big_int.big_int; e : Big_int.big_int}

type pubkey_info =
  | PK_RSA of rsa_pubkey_info
  | PK_Other of (algoId * string)


type tbsCertificate = {
  version : int option;
  serial : Big_int.big_int;
  sig_algo : algoId;
  issuer : dn;
  validity : validity;
  subject : dn;
  pkinfo : pubkey_info;
  issuerUniqueId : string option;
  subjectUniqueId : string option;
  extensions : ext list
}
type certificate = {
  tbs : tbsCertificate;
  cert_sig_algo : algoId;
  signature : Big_int.big_int
}


let extract_rdn r =
  match r with
    | (Asn1.C_Universal, 17, Asn1.Constructed [Asn1.C_Universal, 16, Asn1.Constructed a]) -> [extract_atv a]
    | (Asn1.C_Universal, 17, Asn1.Constructed _) -> failwith "RDN must contain exactly one ATV"
    | _ -> failwith "Invalid RDN"

let extract_dn d = List.map extract_rdn d

(* TODO *)
let extract_date t d = d

(* TODO *)
let extract_rsa_key s =
  match (exact_parse s) with
    | (Asn1.C_Universal, 16, Asn1.Constructed 
      [(Asn1.C_Universal, 2, Asn1.Integer n);
       (Asn1.C_Universal, 2, Asn1.Integer e)]) -> {n = n; e = e}
    | _ -> failwith "Invalid RSA public key"

let extract_pubkey_info a s = 
  match extract_algoId a with
    | PubKeyAlgo (PKA_RSA) -> PK_RSA (extract_rsa_key s)
    | OtherAlgo oid -> PK_Other (OtherAlgo oid, s)
    | _ -> failwith "Invalid algoId in public key info"

let extract_uniqueId lst =
  match lst with
    | (Asn1.C_ContextSpecific, 1, Asn1.BitString (n, id))::r ->
      if n = 0
      then (Some id, r)
      else failwith "Unique identifier with nBits != 0 not supported"
    | _ -> (None, lst)

  

let extract_tbsCertificate tbs =
  let v, afterV = match tbs with
    | (Asn1.C_ContextSpecific, 0, Asn1.Constructed
        [(Asn1.C_Universal, 2, Asn1.Integer i)])::r -> (Some (Big_int.int_of_big_int i), r)
    | _ -> (None, tbs)
  in
  let sn, sa, issuer, validity, subject, pkinfo, afterPkInfo = match afterV with
    | (Asn1.C_Universal, 2, Asn1.Integer num)::
	(Asn1.C_Universal, 16, Asn1.Constructed alg1)::
	(Asn1.C_Universal, 16, Asn1.Constructed i)::
	(Asn1.C_Universal, 16, Asn1.Constructed
	  [(Asn1.C_Universal, nbt, Asn1.String notBefore); 
	   (Asn1.C_Universal, nat, Asn1.String notAfter)])::
	(Asn1.C_Universal, 16, Asn1.Constructed s)::
	(Asn1.C_Universal, 16, Asn1.Constructed
	  [(Asn1.C_Universal, 16, Asn1.Constructed alg2);
	   (Asn1.C_Universal, 3, Asn1.BitString (n, pk))])::r ->
	 if n = 0
	 then (num, extract_algoId alg1, extract_dn i,
	       (extract_date nbt notBefore, extract_date nat notAfter),
	       extract_dn s, extract_pubkey_info alg2 pk, r)
	 else failwith "Public key with nBits != 0 not supported"
    | _ -> failwith "Wrong content in the tbsCertificate"
  in
  let issuerUniqueId, afterIUI = extract_uniqueId afterPkInfo in
  let subjectUniqueId, afterSUI = extract_uniqueId afterIUI in
  let extensions = match afterSUI with
    | [(Asn1.C_ContextSpecific, 3, Constructed
      [(Asn1.C_Universal, 16, Constructed (e::exts))])] ->
      List.map extract_extension (e::exts)
    | _ -> failwith "Wrong content in the tbsCertificate"
  in
  { version = v; serial = sn; sig_algo = sa; issuer = issuer;
    validity = validity; subject = subject; pkinfo = pkinfo;
    issuerUniqueId = issuerUniqueId; subjectUniqueId = subjectUniqueId;
    extensions = extensions}


let extract_certificate c =
  match c with
    | [(Asn1.C_Universal, 16, Asn1.Constructed tbs_s);
       (Asn1.C_Universal, 16, Asn1.Constructed sa);
       (Asn1.C_Universal, 3, Asn1.BitString (n, s))] ->
      if n = 0
      then {tbs = extract_tbsCertificate tbs_s;
	    cert_sig_algo = extract_algoId sa;
	    signature = Asn1.bigint_of_intlist (Asn1.intlist_of_string s)}
      else failwith "Signature field with nBits != 0 not supported"
    | _ -> failwith "Wrong content in the certifiacte"

let string_to_certificate s : certificate =
  match (exact_parse s) with 
    | (Asn1.C_Universal, 16, Asn1.Constructed cert) -> extract_certificate cert
    | _ -> failwith "Sequence expected at certificate level"
*)
