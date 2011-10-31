open X509
open ParsingEngine
open Asn1
open Asn1Constraints


(* Basic Constraints *)

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




(* Subject Key Identifier *)

let subjectKeyIdentifier_oid = [85;29;14]

let mkSKI = Simple_cons (C_Universal, false, 4, "subjectKeyIdentifier",
			 fun pstate -> SubjectKeyIdentifier (Asn1.Engine.pop_string pstate))



(* Authority Key Identifier *)
let authorityKeyIdentifier_oid = [85;29;35]

let aki_constraint = {
  severity_if_too_many_objects = s_specfatallyviolated;
  constraint_list = [
    Simple_cons (C_ContextSpecific, false, 0, "keyIdentifier", der_to_octetstring true), s_ok;
    Simple_cons (C_ContextSpecific, true, 1, "authorityCertIssuer", der_to_constructed), s_ok;
    Simple_cons (C_ContextSpecific, false, 2, "authorityCertSerialNumber", der_to_int), s_ok
  ]
}

let extract_aki = function
  | (String (s, true))::_ -> AuthorityKeyIdentifier (AKI_KeyIdentifier s)
  (* TODO *)
  | _ -> AuthorityKeyIdentifier AKI_Unknown

let mkAKI = Simple_cons (C_Universal, true, 16, "basicConstraints",
			 parse_constrained_sequence extract_aki aki_constraint)




(* CRL Distribution Point *)

let crlDistributionPoint_oid = [85;29;31]


let authorityInfoAccess_oid = [43;6;1;5;5;7;1;1]
let keyUsage_oid = [85;29;15]
let extKeyUsage_oid = [85;29;37]
let ocsp_oid = [43;6;1;5;5;7;48;1]









(*let dp_constraint = {
  severity_if_too_many_objects = s_specfatallyviolated;
  constraint_list = [
    Simple_cons (C_ContextSpecific, true, 0, "DistributionPointName", der_to_constructed), s_ok;
    Simple_cons (C_ContextSpecific, false, 1, "ReasonFlags", der_to_bitstring), s_ok;
    Simple_cons (C_ContextSpecific, true, 2, "cRLIssuer", der_to_constructed), s_ok
  ]
}

let extract_dp = 

let distributionPoint_cons = Simple_cons (C_Universal, true, 16, "distributionPoint",
					  parse_constrained_sequence extract_dp dp_constraint)

let mkCRLDP = Simple_cons (C_Universal, true, 16, "cRLDistributionPoint",
			   parse_sequenceof Common.identity distributionPoint_cons (AtLeast (1, s_speclightlyviolated)))

parse_sequenceof (postprocess : 'a list -> 'b) (cons : 'a asn1_constraint)
                         (n : number_constraint) (pstate : parsing_state) : 'b =
  
/* From RFC 5280
DistributionPointName ::= CHOICE {
  fullName                [0]     GeneralNames,
  nameRelativeToCRLIssuer [1]     RelativeDistinguishedName
}

What is really coded here is:
DistributionPointName ::= SEQUENCE {
  fullName                [0]     GeneralNames OPTIONAL,
  nameRelativeToCRLIssuer [1]     RelativeDistinguishedName OPTIONAL
}
*/

/* From RFC 5280
DistributionPoint ::= SEQUENCE {
  distributionPoint       [0]     DistributionPointName OPTIONAL,
  reasons                 [1]     ReasonFlags OPTIONAL,
  cRLIssuer               [2]     GeneralNames OPTIONAL
}
*/
CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint



let mkCRLDistributionPoint s =
  let asn1struct = Asn1.exact_parse s in
  match asn1struct with
    | (Asn1.C_Universal, 16, Asn1.Constructed
      [(Asn1.C_Universal, 16, Asn1.Constructed
	[(Asn1.C_ContextSpecific, 0, Asn1.Constructed
	  [(Asn1.C_ContextSpecific, 0, Asn1.Constructed
	    [(Asn1.C_ContextSpecific, 6, Asn1.Unknown url)])])])]) -> CRLDistributionPoint url
    | _ -> failwith "Invalid or unknown CRL distribution point"*)




(*

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
  Hashtbl.add extension_directory subjectKeyIdentifier_oid mkSKI;
  Hashtbl.add name_directory authorityKeyIdentifier_oid "authorityKeyIdentifier";
  Hashtbl.add extension_directory authorityKeyIdentifier_oid mkAKI;
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
