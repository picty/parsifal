open Parsifal
open PTypes
open Asn1Engine
open Asn1PTypes
open X509Basics


(****************)
(* General Name *)
(****************)

(* TODO? *)
(* OtherName ::= SEQUENCE { *)
(*      type-id    OBJECT IDENTIFIER, *)
(*      value      [0] EXPLICIT ANY DEFINED BY type-id } *)

(* ORAddress ::= SEQUENCE { *)
(*    built-in-standard-attributes BuiltInStandardAttributes, *)
(*    built-in-domain-defined-attributes *)
(*                    BuiltInDomainDefinedAttributes OPTIONAL, *)
(*    -- see also teletex-domain-defined-attributes *)
(*    extension-attributes ExtensionAttributes OPTIONAL } *)

(* EDIPartyName ::= SEQUENCE { *)
(*      nameAssigner            [0]     DirectoryString OPTIONAL, *)
(*      partyName               [1]     DirectoryString } *)

(* TODO: Make the exhaustive meaningful *)
asn1_union generalName [enrich; exhaustive] (UnparsedGeneralName) =
  | (C_ContextSpecific, true, T_Unknown 0) as h -> OtherName of der_object_content (h)
  | C_ContextSpecific, false, T_Unknown 1 -> Rfc822Name of der_printable_octetstring_content (no_constraint) (* IA5 *)
  | C_ContextSpecific, false, T_Unknown 2 -> DNSName of der_printable_octetstring_content (no_constraint) (* IA5 *)
  | (C_ContextSpecific, true, T_Unknown 3) as h -> X400Address of der_object_content (h)
  | C_ContextSpecific, true, T_Unknown 4 -> DirectoryName of distinguishedName
  | (C_ContextSpecific, true, T_Unknown 5) as h -> EDIPartyName of der_object_content (h)
  | C_ContextSpecific, false, T_Unknown 6 -> UniformResourceIdentifier of der_printable_octetstring_content (no_constraint) (* IA5 *)
  | C_ContextSpecific, false, T_Unknown 7 -> IPAddress of der_octetstring_content (no_constraint)
  | C_ContextSpecific, false, T_Unknown 8 -> RegisteredID of der_oid_content
asn1_alias generalNames = seq_of generalName




(****************************)
(* Authority Key Identifier *)
(****************************)

struct authorityKeyIdentifier_content = {
  optional keyIdentifier : asn1 [(C_ContextSpecific, false, T_Unknown 0)] of binstring;
  optional authorityCertIssuer : asn1 [(C_ContextSpecific, true, T_Unknown 1)] of (list of generalName);
  optional authorityCertSerialNumber : asn1 [(C_ContextSpecific, false, T_Unknown 2)] of der_integer_content;
  parse_checkpoint _constraint : both_equal(false; (CustomException "AKI components 1 and 2 should be defined together");
                                            authorityCertIssuer = None; authorityCertSerialNumber = None)
}
asn1_alias authorityKeyIdentifier



(*************)
(* Key Usage *)
(*************)

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



(****************************)
(* Private Key Usage Period *)
(****************************)

(* TODO: Add structural check: at least one field should be present *)
struct privateKeyUsagePeriod_content = {
  optional pkup_notBefore : asn1 [(C_ContextSpecific, false, T_Unknown 0)] of der_generalized_time_content;
  optional pkup_notAfter : asn1 [(C_ContextSpecific, false, T_Unknown 1)] of der_generalized_time_content
}
asn1_alias privateKeyUsagePeriod



(*********************)
(* Basic Constraints *)
(*********************)

struct basicConstraints_content = {
  optional cA : der_boolean;
  optional pathLenConstraint : der_smallint
}
asn1_alias basicConstraints



(*******************)
(* NameConstraints *)
(*******************)

struct generalSubtree_content = {
  gst_base : generalName;
  optional gst_minimum : asn1 [(C_ContextSpecific, true, T_Unknown 0)] of der_integer_content;
  optional gst_maximum : asn1 [(C_ContextSpecific, true, T_Unknown 1)] of der_integer_content
}
asn1_alias generalSubtree
asn1_alias generalSubtrees = seq_of generalSubtree (* TODO: 1 .. MAX *)

(* TODO: Add structural constraint (0 or 1 must be present) *)
struct nameConstraints_content = {
  optional permittedSubtrees : asn1 [(C_ContextSpecific, true, T_Unknown 0)] of generalSubtrees;
  optional excludedSubtrees : asn1 [(C_ContextSpecific, true, T_Unknown 1)] of generalSubtrees
}
asn1_alias nameConstraints



(***************************)
(* CRL Distribution Points *)
(***************************)

(* TODO: Make the exhaustive meaningful *)
asn1_union distributionPointName [enrich; exhaustive] (UnparsedDistributionPointName) =
  | C_ContextSpecific, true, T_Unknown 0 -> FullName of (list of generalName)
  | C_ContextSpecific, true, T_Unknown 1 -> NameRelativeToCRLIssuer of (list of atv)

let reasonFlags_values = [|
  "unused";
  "keyCompromise";
  "caCompromise";
  "affiliationChanged";
  "superseded";
  "cessationOfOperation";
  "certificateHold";
  "privilegeWithdrawn";
  "aaCompromise"
|]

(* TODO: Add structural check: at least 0 or 2 should be present *)
struct distributionPoint_content = {
  optional distributionPoint : asn1 [(C_ContextSpecific, true, T_Unknown 0)] of distributionPointName;
  optional reasons : asn1 [(C_ContextSpecific, true, T_Unknown 1)] of der_enumerated_bitstring_content[reasonFlags_values];
  optional crlIssuer : asn1 [(C_ContextSpecific, true, T_Unknown 2)] of (list of generalName)
}

asn1_alias distributionPoint
asn1_alias crlDistributionPoints = seq_of distributionPoint (* TODO: 1 .. MAX *)



(************************)
(* Certificate Policies *)
(************************)

(* TODO: Make the exhaustive meaningful *)
asn1_union displayText [enrich; exhaustive] (UnparsedDisplayText) =
  | C_Universal, false, T_IA5String -> DT_IA5String of der_octetstring_content (no_constraint)
  | C_Universal, false, T_VisibleString -> DT_VisibleString of der_octetstring_content (no_constraint)
  | C_Universal, false, T_UTF8String -> DT_UTF8String of der_octetstring_content (no_constraint)
  | C_Universal, false, T_BMPString -> DT_BMPString of der_octetstring_content (no_constraint)

struct noticeReference_content = {
  organization : displayText;
  noticeNumbers : asn1 [(C_Universal, true, T_Sequence)] of der_integer
}
asn1_alias noticeReference

struct userNotice_content = {
  optional noticeRef : noticeReference;
  optional explicitText : displayText
}
asn1_alias userNotice

union policyQualifier [enrich] (UnparsedQualifier of der_object) =
  | "id-qt-cps" -> CPSuri of der_ia5string(NoConstraint)
  | "id-qt-unotice" -> UserNotice of userNotice

struct policyQualifierInfo_content = {
  policyQualifierId : der_oid;
  qualifier : policyQualifier(hash_get oid_directory policyQualifierId "")
}
asn1_alias policyQualifierInfo
asn1_alias policyQualifiers = seq_of policyQualifierInfo (* TODO: 1..MAX *)

struct policyInformation_content = {
  policyIdentifer : der_oid;
  optional policyQualifiers : policyQualifiers
}
asn1_alias policyInformation
asn1_alias certificatePolicies = seq_of policyInformation (* 1..MAX *)



(**********************)
(* Extended Key Usage *)
(**********************)

asn1_alias extendedKeyUsage = seq_of der_oid



(********************************)
(* Authority Information Access *)
(********************************)

struct accessDescription_content = {
  accessMethod : der_oid;
  accessLocation : generalName
}
asn1_alias accessDescription
asn1_alias authorityInfoAccess = seq_of accessDescription (* TODO: 1 .. MAX *)


(****************)
(* NS Cert Type *)
(****************)

let nsCertType_values = [|
  "SSL Client";
  "SSL Server";
  "S/MIME";
  "Obj Sign";
  "SSL CA";
  "S/MIME CA";
  "Obj Sign CA"
|]



union extnValue [enrich] (UnparsedExtension of binstring) =
  | "authorityKeyIdentifier" -> AuthorityKeyIdentifier of authorityKeyIdentifier
  | "subjectKeyIdentifier" -> SubjectKeyIdentifier of der_octetstring
  | "keyUsage" -> KeyUsage of der_enumerated_bitstring[keyUsage_values]
  | "privateKeyUsagePeriod" -> PrivateKeyUsagePeriod of privateKeyUsagePeriod
  | "subjectAltName" -> SubjectAltName of generalNames
  | "issuerAltName" -> IssuerAltName of generalNames
  | "basicConstraints" -> BasicConstraints of basicConstraints
  | "nameConstraints" -> NameConstraints of nameConstraints
  | "crlDistributionPoints" -> CRLDistributionPoints of crlDistributionPoints
  | "certificatePolicies" -> CertificatePolicies of certificatePolicies
  | "extendedKeyUsage" -> ExtendedKeyUsage of extendedKeyUsage
  | "authorityInfoAccess" -> AuthorityInfoAccess of authorityInfoAccess
  | "nsCertType" -> NSCertType of der_enumerated_bitstring[nsCertType_values]
  | "nsComment" -> NSComment of der_ia5string(NoConstraint)

(* Sordid hack. TODO: auto-generate that with an option laxist? *)
let parse_extnValue t input =
  (* We need the exact=true to avoid failing in the octetstring_container *) 
  match try_parse ~exact:true (parse_extnValue t) input with
  | None -> parse_extnValue "" input
  | Some res -> res


struct extension_content = {
  extnID : der_oid;
  optional critical : der_boolean;
  extnValue : octetstring_container of extnValue(hash_get oid_directory extnID "")
}
asn1_alias extension
asn1_alias extension_list = seq_of extension (* TODO: min = 1 *)
