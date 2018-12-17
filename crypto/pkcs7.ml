open Asn1Engine
open Asn1PTypes
open PTypes
open X509Basics
open X509

alias pkcs1_asn1_struct = hashAlgAndValue

asn1_struct spcIndirectDataContent = {
  data : atv;
  messageDigest : pkcs1_asn1_struct
}

asn1_struct msContentInfo = {
  ms_oid : der_oid;
  contentInfo : asn1 [(C_ContextSpecific, true, T_Unknown 0)] of spcIndirectDataContent
}



asn1_struct issuerAndSerialNumber = {
  issuerDN : distinguishedName;
  issuerSN : der_integer
}


asn1_struct attribute = {
  a_oid : der_oid;
  a_content : asn1 [(C_Universal, true, T_Set)] of list of binstring
}

asn1_alias authenticatedAttributes = constructed [C_ContextSpecific, 0] list of attribute
asn1_alias unauthenticatedAttributes = constructed [C_ContextSpecific, 1] list of enrich_blocker(7) of der_object

asn1_struct signerInfo = {
  version : der_smallint;
  issuerAndSerialNumber : issuerAndSerialNumber;
  digestAlgorithm : algorithmIdentifier;
  optional authenticatedAttributesUNPARSED : authenticatedAttributes;
  digestEncryptionAlgorithm : algorithmIdentifier;
  encryptedDigest : der_octetstring;
  optional unAuthenticatedAttributesUNPARSED : unauthenticatedAttributes
}

asn1_alias digestAlgorithmIdentifiers = set_of algorithmIdentifier

asn1_struct pkcs7_signed_data = {
  version : der_smallint;
  digestAlgorithms : digestAlgorithmIdentifiers;
  contentInfo : msContentInfo;
  optional certificates : asn1 [(C_ContextSpecific, true, T_Unknown 0)] of (list of certificate);
  (* XXX parse CRLs *)
  optional crls : asn1 [(C_ContextSpecific, true, T_Unknown 0)] of (list of binstring);
  signerInfos : asn1 [(C_Universal, true, T_Set)] of (list of signerInfo);
  parse_checkpoint : ignore
}

(*
union pkcs7_content_data (Unspecified of der_object) =
  | [42;840;113549;1;7;2] -> SignedData of pkcs7_signed_data
*)

struct pkcs7_content = {
  p7_contenttype : der_oid;
  (*p7_content : pkcs7_content*)
  p7_signed_data : asn1 [(C_ContextSpecific, true, T_Unknown 0)] of pkcs7_signed_data
}
asn1_alias pkcs7


let pkcs_oids = [
(* standard PKCS 7 OIDs, see http://www.alvestrand.no/objectid/1.2.840.113549.1.7.html *)
  "PKCS-7", [42;840;113549;1;7];
  "data", [42;840;113549;1;7;1];
  "signedData", [42;840;113549;1;7;2];
  "envelopedData", [42;840;113549;1;7;3];
  "signedAndEnvelopedData", [42;840;113549;1;7;4];
  "digestedData", [42;840;113549;1;7;5];
  "encryptedData", [42;840;113549;1;7;6];

(* standard PKCS 9 OIDs, see http://www.alvestrand.no/objectid/1.2.840.113549.1.9.html *)
  "PKCS-9 - Signatures", [42;840;113549;1;9];
  "mailAddress", [42;840;113549;1;9;1];
  "PKCS-9 unstructuredName", [42;840;113549;1;9;2];
  "contentType", [42;840;113549;1;9;3];
  "messageDigest", [42;840;113549;1;9;4];

  "Timestamp Token", [42;840;113549;1;9;16;1;4];
  "Signing Certificate", [42;840;113549;1;9;16;2;12];
]

let ms_oids = [
(* taken from http://support.microsoft.com/kb/287547 *)
  "Authenticode", [43;6;1;4;1;311;2];
  "spcIndirectDataContent", [43;6;1;4;1;311;2;1;4];
  "spcStatementType", [43;6;1;4;1;311;2;1;11];
  "spcSpOpusInfo", [43;6;1;4;1;311;2;1;12];
  "spcPEImageData", [43;6;1;4;1;311;2;1;15];
  "spcSPAgencyInfo", [43;6;1;4;1;311;2;1;10];
  "spcMinimalCriteria", [43;6;1;4;1;311;2;1;26];
  "spcFinancialCriteria", [43;6;1;4;1;311;2;1;27];
  "spcLink", [43;6;1;4;1;311;2;1;28];
  "spcHashInfo", [43;6;1;4;1;311;2;1;29];
  "spcSIPInfo", [43;6;1;4;1;311;2;1;30];

  "Time Stamping",  [43;6;1;4;1;311;3];
  "spcTimeStampRequest", [43;6;1;4;1;311;3;2;1];
  "spcRFC3161_counterSign", [43;6;1;4;1;311;3;3;1];

  "Microsoft Enrollment Infrastructure",  [43;6;1;4;1;311;20];
  "AutoEntrollCtlUsage",  [43;6;1;4;1;311;20;1];
  "EnrollCerttypeExtension",  [43;6;1;4;1;311;20;2];
  "EnrollmentAgent",  [43;6;1;4;1;311;20;2;1];
  "KPSmartcardLogon",  [43;6;1;4;1;311;20;2;2];
  "NTPrincipalName",  [43;6;1;4;1;311;20;2;3];
  "CertManifold",  [43;6;1;4;1;311;20;3];

  "Microsoft CertSrv Infrastructure",  [43;6;1;4;1;311;21];
  "Microsoft CertSrv",  [43;6;1;4;1;311;21;1];
]



let _ =
  let register_oids (name, oid) = register_oid oid name in
  List.iter register_oids pkcs_oids;
  List.iter register_oids ms_oids

