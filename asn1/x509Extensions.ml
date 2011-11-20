open Types
open Modules
open Printer
open ParsingEngine
open Asn1
open Asn1Constraints


(* This param is declared here, but is accessible via the x509 module *)
let parse_extensions = ref true

type extension = {
  e_id : int list;
  e_critical : bool option;
  e_content : value
}

let empty_extension = {
  e_id = [];
  e_critical = None;
  e_content = V_Unit
}



type ext_parse = value asn1_constraint
type ext_dump = value -> string
let (extension_directory : (int list, (ext_parse * ext_dump)) Hashtbl.t) = Hashtbl.create 10

let register_extension oid name parse_cons dump_fun =
  register_oid oid name;
  Hashtbl.replace extension_directory oid (parse_cons, dump_fun)




let extension_content_constraint = {
  severity_if_too_many_objects = s_specfatallyviolated;
  constraint_list = [
    Simple_cons (C_Universal, false, 6, "ExtensionId", der_to_oid), s_specfatallyviolated;
    Simple_cons (C_Universal, false, 1, "Critical", der_to_boolean), s_ok;
    Simple_cons (C_Universal, false, 4, "ExtensionValue", der_to_octetstring true), s_specfatallyviolated
  ]
}

let deep_parse_ext id s =
  if not !parse_extensions then V_BinaryString s else
    try
      let ext_cons, _ = Hashtbl.find extension_directory id in
      let pstate = pstate_of_string (Some (string_of_oid id)) s in
      constrained_parse_def ext_cons s_speclightlyviolated (V_BinaryString s) pstate
    with Not_found -> V_BinaryString s

let extract_ext = function
  | [OId id; Boolean b; String (s, true)] ->
    { e_id = id; e_critical = Some b; e_content = deep_parse_ext id s }
  | [OId id; String (s, true)] ->
    { e_id = id; e_critical = None; e_content = deep_parse_ext id s }
  | _ -> empty_extension


let extension_constraint = Simple_cons (C_Universal, true, 16, "Extension",
					parse_constrained_sequence extract_ext extension_content_constraint)
let extensions_constraint = seqOf_cons Common.identity "Extensions" extension_constraint (AtLeast (1, s_speclightlyviolated))


(* TODO: Improve this *)
let string_of_extension ext =
  let id_str = (string_of_oid ext.e_id) in
  let critical_str = match ext.e_critical with
    | None -> ""
    | Some true -> " (critical)"
    | Some false -> " (not critical)"
  in
  PrinterLib._string_of_value (Some (id_str ^ critical_str)) true ext.e_content


module ExtensionParser = struct
  let name = "extension"
  type t = extension
  let params = []

  let parse = constrained_parse extension_constraint

  let dump ext = raise (NotImplemented "extension.dump")

  let enrich ext dict =
    Hashtbl.replace dict "id" (Asn1Parser.value_of_oid  ext.e_id);
    begin
      match ext.e_critical with
	| None -> ()
	| Some critical -> Hashtbl.replace dict "critical" (V_Bool critical)
    end;
    Hashtbl.replace dict "content" ext.e_content;
    ()

  let update dict = raise (NotImplemented "extension.update")

  let to_string = string_of_extension
  let functions = []
end

module ExtensionModule = MakeParserModule (ExtensionParser)
let _ = add_object_module ((module ExtensionModule : ObjectModule))



(* Basic Constraints *)

let basicConstraints_oid = [85;29;19]

let bc_constraint = {
  severity_if_too_many_objects = s_specfatallyviolated;
  constraint_list = [
    Simple_cons (C_Universal, false, 1, "CA", der_to_boolean), s_ok;
    Simple_cons (C_Universal, false, 2, "PathLen", der_to_int), s_ok
  ]
}

let extract_bc l =
  let res = Hashtbl.create 2 in
  let add_ca b = Hashtbl.replace res "CA" (V_Bool b)
  and add_pl i = Hashtbl.replace res "PathLen" (V_Bigint i) in
  begin
    match l with
      | [Boolean b; Integer i] -> add_ca b; add_pl i
      | [Boolean b] -> add_ca b
      | [Integer i] -> add_pl i
      | _ -> ()
  end;
  V_Dict res

let mkBasicConstraints = Simple_cons (C_Universal, true, 16, "basicConstraints",
				      parse_constrained_sequence extract_bc bc_constraint)

let dump_basicConstraints v =
  let d = eval_as_dict v in
  let ca_obj =
    try [mk_object' "" C_Universal 1 (Boolean (eval_as_bool (Hashtbl.find d "CA")))]
    with Not_found -> []
  and pl_obj =
    try [mk_object' "" C_Universal 2 (Integer (eval_as_string (Hashtbl.find d "PathLen")))]
    with Not_found -> []
  in dump (mk_object' "" C_Universal 16 (Constructed (ca_obj@pl_obj)))

let _ = register_extension basicConstraints_oid "basicConstraints" mkBasicConstraints dump_basicConstraints



(* Key Usage *)

let keyUsage_oid = [85;29;15]
let keyUsage_values = [|
  "digitalSignature";
  "nonRepudiation";
  "keyEncipherment";
  "dataEncipherment";
  "keyAgreement";
  "keyCertSign";
  "cRLSign";
  "encipherOnly";
  "decipherOnly"
|]

let extract_KeyUsage pstate =
  let nBits, content = raw_der_to_bitstring pstate in
  let l = enumerated_from_raw_bit_string pstate keyUsage_values nBits content in
  V_List (List.map (fun x -> V_Enumerated (x, apply_desc keyUsage_values)) l)

let mkKeyUsage = Simple_cons (C_Universal, false, 3, "keyUsage", extract_KeyUsage)

let dump_KeyUsage v = raise (NotImplemented "dump_KeyUsage")

let _ = register_extension keyUsage_oid "keyUsage" mkKeyUsage dump_KeyUsage



(* Extended Key Usage *)

let extKeyUsage_oid = [85;29;37]

let extract_EKU l = V_List (List.map Asn1Parser.value_of_oid l)
let mkExtKeyUsage = seqOf_cons extract_EKU "extendedKeyUsage" oid_cons (AtLeast (1, s_speclightlyviolated))

let dump_ExtKeyUsage v = raise (NotImplemented "dump_ExtKeyUsage")


let _ = register_extension extKeyUsage_oid "extendedKeyUsage" mkExtKeyUsage dump_ExtKeyUsage



(* Subject Key Identifier *)

let subjectKeyIdentifier_oid = [85;29;14]

let mkSKI = Simple_cons (C_Universal, false, 4, "subjectKeyIdentifier",
			 fun pstate -> V_BinaryString (pop_string pstate))

let dump_SKI v = dump (mk_object' "" C_Universal 4 (String (eval_as_string v, true)))

let _ = register_extension subjectKeyIdentifier_oid "subjectKeyIdentifier" mkSKI dump_SKI



(* Authority Key Identifier *)
let authorityKeyIdentifier_oid = [85;29;35]

let aki_constraint = {
  severity_if_too_many_objects = s_specfatallyviolated;
  constraint_list = [
    Simple_cons (C_ContextSpecific, false, 0, "keyIdentifier", der_to_octetstring true), s_ok;
    (* TODO: Do better than that *)
    Simple_cons (C_ContextSpecific, true, 1, "authorityCertIssuer", der_to_constructed), s_ok;
    Simple_cons (C_ContextSpecific, false, 2, "authorityCertSerialNumber", der_to_int), s_ok
  ]
}

let extract_aki aki =
  let res = Hashtbl.create 3 in
  let extract_serial = function
    | (Integer i)::_ -> Hashtbl.replace res "authorityCertSerialNumber" (V_Bigint i)
    | _ -> () in
  (* TODO: Do better than that *)
  let extract_cert_issuer = function
    | (Constructed l)::r ->
      Hashtbl.replace res "authorityCertIssuer" (V_List (List.map Asn1Module.register l));
      extract_serial r
    | r -> extract_serial r in
  let extract_key_identifier = function
    | (String (s, true))::r ->
      Hashtbl.replace res "keyIdentifier" (V_BinaryString s);
      extract_cert_issuer r
    | r -> extract_cert_issuer r in
  extract_key_identifier aki;
  V_Dict res

let mkAKI = Simple_cons (C_Universal, true, 16, "authorityKeyIdentifier",
			 parse_constrained_sequence extract_aki aki_constraint)

let dump_AKI v = raise (NotImplemented "dump_AKI")

let _ = register_extension authorityKeyIdentifier_oid "authorityKeyIdentifier" mkAKI dump_AKI



(* NSComment *)

let nsComment_oid = [96;16;840;1;113730;1;13]

let mkNSComment = Simple_cons (C_Universal, false, 22, "nsComment", fun pstate -> V_String (pop_string pstate))

let dump_NSComment v = dump (mk_object' "" C_Universal 22 (String (eval_as_string v, false)))

let _ = register_extension nsComment_oid "nsComment" mkNSComment dump_NSComment



(* NS Cert Type *)

let nsCertType_oid = [96;16;840;1;113730;1;1]
let nsCertType_values = [|
  "client";
  "server";
  "email";
  "objsign";
  "reserved";
  "sslCA";
  "emailCA";
  "objCA"
|]

let extract_NSCertType pstate =
  let nBits, content = raw_der_to_bitstring pstate in
  let l = enumerated_from_raw_bit_string pstate nsCertType_values nBits content in
  V_List (List.map (fun x -> V_Enumerated (x, apply_desc nsCertType_values)) l)

let mkNSCertType = Simple_cons (C_Universal, false, 3, "nsCertType", extract_NSCertType)

let dump_NSCertType v = raise (NotImplemented "dump_NSCertType")

let _ = register_extension nsCertType_oid "nsCertType" mkNSCertType dump_NSCertType



(*

(* CRL Distribution Point *)

let crlDistributionPoint_oid = [85;29;31]


let authorityInfoAccess_oid = [43;6;1;5;5;7;1;1]
let ocsp_oid = [43;6;1;5;5;7;48;1]






let dp_constraint = {
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


*)
