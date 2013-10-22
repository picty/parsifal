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
  let _ = X509.parse_certificate in
  if Array.length Sys.argv <> 2 then failwith "Argument expected"
  let input = string_input_of_filename Sys.argv.(1) in
  let csr = parse_certificationRequest input in
  print_endline (print_value (value_of_certificationRequest csr))
