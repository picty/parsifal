open X509
open ParsingEngine
open Asn1
open Asn1Constraints


let basicConstraints_oid = [85;29;19]

let bc_constraint = {
  severity_if_too_many_objects = s_specfatallyviolated;
  constraint_list = [
    Simple_cons (C_Universal, false, 1, "CA", der_to_boolean), s_ok;
    Simple_cons (C_Universal, false, 2, "PathLen", der_to_int), s_ok
  ]
}

let extract_bc = function
  | [Boolean b; Integer i] -> BasicConstraints (Some b, Some i)
  | [Boolean b] -> BasicConstraints (Some b, None)
  | [Integer i] -> BasicConstraints (None, Some i)
  | [] -> BasicConstraints (None, None)
  | _ -> InvalidExt

let mkBasicConstraints = Simple_cons (C_Universal, true, 16, "basicConstraints",
				      parse_constrained_sequence extract_bc bc_constraint)



let subjectKeyIdentifier_oid = [85;29;14]
let authorityKeyIdentifier_oid = [85;29;35]
let crlDistributionPoint_oid = [85;29;31]
let authorityInfoAccess_oid = [43;6;1;5;5;7;1;1]
let keyUsage_oid = [85;29;15]
let extKeyUsage_oid = [85;29;37]
let ocsp_oid = [43;6;1;5;5;7;48;1]



(*let mkSKI s =
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
    | _ -> failwith "Invalid extended key usage"*)


let add_extensions () =
  Hashtbl.add name_directory basicConstraints_oid "basicConstraints";
  Hashtbl.add extension_directory basicConstraints_oid mkBasicConstraints;
  Hashtbl.add name_directory subjectKeyIdentifier_oid "subjectKeyIdentifier";
(*  Hashtbl.add extension_directory subjectKeyIdentifier_oid mkSKI;*)
  Hashtbl.add name_directory authorityKeyIdentifier_oid "authorityKeyIdentifier";
(*  Hashtbl.add extension_directory authorityKeyIdentifier_oid mkAKI;*)
  Hashtbl.add name_directory crlDistributionPoint_oid "crlDistributionPoint";
(*  Hashtbl.add extension_directory crlDistributionPoint_oid mkCRLDistributionPoint;*)
  Hashtbl.add name_directory authorityInfoAccess_oid "authorityInfoAccess";
(*  Hashtbl.add extension_directory authorityInfoAccess_oid mkAuthorityInfoAccess;*)
  Hashtbl.add name_directory keyUsage_oid "keyUsage";
(*  Hashtbl.add extension_directory keyUsage_oid mkKeyUsage;*)
  Hashtbl.add name_directory extKeyUsage_oid "extKeyUsage";
(*  Hashtbl.add extension_directory extKeyUsage_oid mkExtKeyUsage; *)
  ()


let _ =
  add_extensions ();;
