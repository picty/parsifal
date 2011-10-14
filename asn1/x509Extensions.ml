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

