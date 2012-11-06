open Parsifal
open Asn1PTypes

asn1_alias x509_version = constructed [C_ContextSpecific, 0] der_integer

(* TODO: name should rely on Objects written in x509Util.ml *)
struct atv_content = {
  attributeType : der_oid;
  attributeValue : der_object
}
asn1_alias atv

(* TODO: Add constraints on set of [min, max] *)
asn1_alias rdn = set_of atv  (* min = 1 *)
asn1_alias distinguished_name = seq_of rdn


(* TODO: time should be written in x509Util.ml *)
struct validity_content = {
(*  "notBefore", AT_Custom (None, "time"), false, None;
  "notAfter",  AT_Custom (None, "time"), false, None; *)
  notBefore : der_object;
  notAfter : der_object
}
asn1_alias validity


asn1_alias issuerUniqueId = primitive [C_ContextSpecific, 1] der_bitstring
asn1_alias subjectUniqueId = primitive [C_ContextSpecific, 2] der_bitstring


(* TODO: Make extnValue depend on extnID, and have it enrichable *)
asn1_alias extnValue = primitive [T_OctetString] der_octetstring_content(no_constraint)

struct extension_content = {
  extnID : der_oid;
  optional critical : der_boolean;
  extnValue : extnValue
}
asn1_alias extension

asn1_alias extension_list = seq_of extension (* min = 1 *)
asn1_alias extensions = constructed [C_ContextSpecific, 3] extension_list


struct tbsCertificate_content = {
  optional version : x509_version;
  serialNumber : der_integer;
  signature : X509Util.algorithmIdentifier;
  issuer : distinguished_name;
  validity : validity;
  subject : distinguished_name;
  subjectPublicKeyInfo : X509Util.subjectPublicKeyInfo;
  optional issuerUniqueId : issuerUniqueId;
  optional subjectUniqueId : subjectUniqueId;
  optional extensions : extensions
}
asn1_alias tbsCertificate

struct certificate_content = {
  tbsCertificate : tbsCertificate;
  signatureAlgorithm : X509Util.algorithmIdentifier;
  signatureValue : der_bitstring
}
asn1_alias certificate [top]
