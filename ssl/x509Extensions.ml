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

asn1_struct authorityKeyIdentifier = {
  optional keyIdentifier : asn1 [(C_ContextSpecific, false, T_Unknown 0)] of binstring;
  optional authorityCertIssuer : asn1 [(C_ContextSpecific, true, T_Unknown 1)] of (list of generalName);
  optional authorityCertSerialNumber : asn1 [(C_ContextSpecific, false, T_Unknown 2)] of der_integer_content;
  parse_checkpoint : both_equal(false; (CustomException "AKI components 1 and 2 should be defined together");
                                authorityCertIssuer = None; authorityCertSerialNumber = None)
}



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
asn1_struct privateKeyUsagePeriod = {
  optional pkup_notBefore : asn1 [(C_ContextSpecific, false, T_Unknown 0)] of der_generalized_time_content;
  optional pkup_notAfter : asn1 [(C_ContextSpecific, false, T_Unknown 1)] of der_generalized_time_content
}



(*********************)
(* Basic Constraints *)
(*********************)

asn1_struct basicConstraints = {
  optional cA : der_boolean;
  optional pathLenConstraint : der_smallint
}



(*******************)
(* NameConstraints *)
(*******************)

asn1_struct generalSubtree = {
  gst_base : generalName;
  optional gst_minimum : asn1 [(C_ContextSpecific, true, T_Unknown 0)] of der_integer_content;
  optional gst_maximum : asn1 [(C_ContextSpecific, true, T_Unknown 1)] of der_integer_content
}
asn1_alias generalSubtrees = seq_of generalSubtree (* TODO: 1 .. MAX *)

(* TODO: Add structural constraint (0 or 1 must be present) *)
asn1_struct nameConstraints = {
  optional permittedSubtrees : asn1 [(C_ContextSpecific, true, T_Unknown 0)] of generalSubtrees;
  optional excludedSubtrees : asn1 [(C_ContextSpecific, true, T_Unknown 1)] of generalSubtrees
}



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
asn1_struct distributionPoint = {
  optional distributionPoint : asn1 [(C_ContextSpecific, true, T_Unknown 0)] of distributionPointName;
  optional reasons : asn1 [(C_ContextSpecific, true, T_Unknown 1)] of der_enumerated_bitstring_content[reasonFlags_values];
  optional crlIssuer : asn1 [(C_ContextSpecific, true, T_Unknown 2)] of (list of generalName)
}

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

asn1_struct noticeReference = {
  organization : displayText;
  noticeNumbers : asn1 [(C_Universal, true, T_Sequence)] of der_integer
}

asn1_struct userNotice = {
  optional noticeRef : noticeReference;
  optional explicitText : displayText
}

union policyQualifier [enrich] (UnparsedQualifier of der_object) =
  | "id-qt-cps" -> CPSuri of der_ia5string(NoConstraint)
  | "id-qt-unotice" -> UserNotice of userNotice

asn1_struct policyQualifierInfo = {
  policyQualifierId : der_oid;
  qualifier : policyQualifier(hash_get oid_directory policyQualifierId "")
}
asn1_alias policyQualifiers = seq_of policyQualifierInfo (* TODO: 1..MAX *)

asn1_struct policyInformation = {
  policyIdentifer : der_oid;
  optional policyQualifiers : policyQualifiers
}
asn1_alias certificatePolicies = seq_of policyInformation (* 1..MAX *)



(**********************)
(* Extended Key Usage *)
(**********************)

asn1_alias extendedKeyUsage = seq_of der_oid



(********************************)
(* Authority Information Access *)
(********************************)

asn1_struct accessDescription = {
  accessMethod : der_oid;
  accessLocation : generalName
}
asn1_alias authorityInfoAccess = seq_of accessDescription (* TODO: 1 .. MAX *)


(************)
(* Logotype *)
(************)

asn1_struct logotypeReference = {
  refStructHash : asn1 [h_sequence] of list of hashAlgAndValue; (* [1..MAX] *)
  refStructURI : asn1 [h_sequence] of list of der_ia5string(NoConstraint); (* [1..MAX] *)
}

asn1_struct logotypeAudioInfo = {
  fileSize : der_smallint; (* Possible Integer overflow *)
  playTime : der_smallint; (* Possible Integer overflow *)
  channels : der_smallint;
  optional sampleRate : asn1 [(C_ContextSpecific, false, T_Unknown 3)] of der_smallint;
  optional language : asn1 [(C_ContextSpecific, false, T_Unknown 4)] of der_printable_octetstring_content (no_constraint) (* IA5 *)
}

asn1_union logotypeImageResolution [enrich; exhaustive] (UnparsedLogotypeImageResolution) =
  | C_ContextSpecific, false, T_Unknown 1 -> LIR_NumBits of der_smallint
  | C_ContextSpecific, false, T_Unknown 2 -> LIR_TableSize of der_smallint

enum logotypeImageType (8, UnknownVal LIT_Unknown) =
  | 0 -> LIT_GrayScale, "grayScale"
  | 1 -> LIT_Color, "color"

asn1_struct logotypeImageInfo = {
  optional lii_type : asn1 [(C_ContextSpecific, false, T_Unknown 0)] of logotypeImageType;
  fileSize : der_smallint; (* Possible Integer overflow *)
  xSize : der_smallint; (* Possible Integer overflow *)
  ySize : der_smallint; (* Possible Integer overflow *)
  optional resolution : logotypeImageResolution;
  optional language : asn1 [(C_ContextSpecific, false, T_Unknown 4)] of der_printable_octetstring_content (no_constraint) (* IA5 *)
}

asn1_struct logotypeDetails = {
  media_type : der_ia5string(NoConstraint);
  logotypeHash : asn1 [h_sequence] of list of hashAlgAndValue; (* [1..MAX] *)
  logotypeURI : asn1 [h_sequence] of list of der_ia5string(NoConstraint); (* [1..MAX] *)
}

asn1_struct logotypeAudio = {
  audioDetails : logotypeDetails;
  optional audioInfo : logotypeAudioInfo;
}

asn1_struct logotypeImage = {
  imageDetails : logotypeDetails;
  optional imageInfo : logotypeImageInfo;
}

asn1_struct logotypeData = {
  optional image : asn1 [h_sequence] of list of logotypeImage;
  optional audio : asn1 [(C_ContextSpecific, true, T_Unknown 1)] of list of logotypeAudio;
}

asn1_union logotypeInfo [enrich; exhaustive] (UnparsedLogotypeInfo) =
  | C_ContextSpecific, true, T_Unknown 0 -> LI_Direct of logotypeData_content
  | C_ContextSpecific, true, T_Unknown 1 -> LI_Indirect of logotypeReference_content
asn1_alias logotypeInfos = seq_of logotypeInfo

asn1_struct otherLogotypeInfo = {
  logotypeType : der_oid;
  oli_info : logotypeInfo;
}
asn1_alias otherLogotypeInfos = seq_of otherLogotypeInfo

asn1_struct logotype = {
  optional communityLogos : asn1 [(C_ContextSpecific, true, T_Unknown 0)] of logotypeInfos;
  optional issuerLogo : asn1 [(C_ContextSpecific, true, T_Unknown 1)] of logotypeInfo;
  optional subjectLogo : asn1 [(C_ContextSpecific, true, T_Unknown 2)] of logotypeInfo;
  optional otherLogos : asn1 [(C_ContextSpecific, true, T_Unknown 3)] of otherLogotypeInfos;
}


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


(***********************)
(* S/MIME Capabilities *)
(***********************)

type capabilityType =
  | CT_Int
  | CT_Null
  | CT_Unknown

let capabilityType_directory : (int list, capabilityType) Hashtbl.t = Hashtbl.create 10

let populate_cap_directory (id, name, value) =
  register_oid id name;
  Hashtbl.replace capabilityType_directory id value;

union capabilityParam [enrich] (UnparsedCapabilityParam of der_object) =
  | CT_Int -> CapabilityLength of der_smallint
  | CT_Null -> CapabilityNull of der_null

asn1_struct sMIMECapability = {
  capability : der_oid;
  optional parameters : capabilityParam(hash_get capabilityType_directory capability CT_Unknown)
}
asn1_alias sMIMECapabilities = seq_of sMIMECapability


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
  | "logotype" -> Logotype of logotype
  | "nsCertType" -> NSCertType of der_enumerated_bitstring[nsCertType_values]
  | "nsBaseURL" -> NSBaseURL of der_ia5string(NoConstraint)
  | "nsRevocationURL" -> NSRevocationURL of der_ia5string(NoConstraint)
  | "nsCARevocationURL" -> NSCARevocationURL of der_ia5string(NoConstraint)
  | "nsRenewalURL" -> NSRenewalURL of der_ia5string(NoConstraint)
  | "nsCAPolicyURL" -> NSCAPolicyURL of der_ia5string(NoConstraint)
  | "nsSSLServerName" -> NSSSLServerName of der_ia5string(NoConstraint)
  | "nsComment" -> NSComment of der_ia5string(NoConstraint)
  | "sMIMECapabilities" -> SMIMECapabilities of sMIMECapabilities
  | "PARSING_FAILURE" -> ExtensionParsingFailure of binstring


asn1_struct extension = {
  extnID : der_oid;
  optional critical : der_boolean;
  extnValue : octetstring_container of exact_safe_union(hash_get oid_directory extnID ""; "PARSING_FAILURE") of extnValue
  (* The exact is needed to avoid generating an error due to trailing stuff in the octetstring_container. *)
}
asn1_alias extension_list = seq_of extension (* TODO: min = 1 *)
