open Parsifal
open Asn1Engine
open Asn1PTypes
open X509
open X509Basics
open X509Extensions

asn1_struct revokedCertificate = {
  userCertificate : der_integer;
  revocationDate : der_time;
  optional crlEntryExtensions : extension_list
}

asn1_alias revokedCertificates = seq_of revokedCertificate  (* min = 1 *)

asn1_struct tbsCertList = {
  optional version : der_smallint;
  signature : algorithmIdentifier;
  issuer : distinguishedName;
  thisUpdate : der_time;
  optional nextUpdate :	der_time;
  optional revokedCertificates : revokedCertificates;
  optional crlExtensionscrlExtensions : asn1 [(C_ContextSpecific, true, T_Unknown 0)] of extension_list;
}

asn1_struct certificateList = {
  tbsCertList : tbsCertList;
  signatureAlgorithm : algorithmIdentifier;
  signatureValue : bitstring_container of signature(signatureType_of_algo signatureAlgorithm)
}
