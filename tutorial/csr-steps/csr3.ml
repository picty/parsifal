open Parsifal
open Asn1Engine
open Asn1PTypes
open X509Basics
open X509
open Pkcs1

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

let check_rsa_sig csr =
  let csr_raw = exact_dump dump_certificationRequestInfo csr.certificationRequestInfo in
  match csr.certificationRequestInfo.subjectPublicKeyInfo.subjectPublicKey, csr.signatureValue with
    | RSA {p_modulus = n; p_publicExponent = e}, RSASignature s ->
      (try ignore (Pkcs1.raw_verify 1 csr_raw s n e); true with Pkcs1.PaddingError -> false)
    | _ -> failwith "Unknown signature"

let check_no_nullchar csr =
  let dn = csr.certificationRequestInfo.name in
  try
    ignore (String.index (string_of_distinguishedName dn) '\x00');
    false
  with Not_found -> true


let _ =
  if Array.length Sys.argv <> 2 then failwith "Argument expected"
  let input = string_input_of_filename Sys.argv.(1) in
  let csr = parse_certificationRequest input in
  if not (check_no_nullchar csr)
  then print_endline "Null character in DN";
  if not (check_rsa_sig csr)
  then print_endline "Invalid RSA signature"
