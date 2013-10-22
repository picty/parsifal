open Parsifal
open Asn1PTypes
open X509Basics

asn1_struct certificationRequestInfo = {
  version : der_smallint;
  name : distinguishedName;
  subjectPublicKeyInfo : subjectPublicKeyInfo;
  attributes : der_object;
}

asn1_struct certificationRequest = {
  certificationRequestInfo : certificationRequestInfo;
  signatureAlgorithm : algorithmIdentifier;
  signatureValue : bitstring_container of signature(signatureType_of_algo signatureAlgorithm)
}

let _ =
  print_endline "Hello, world!"
