open Parsifal
open PTypes
open Asn1Engine
open Asn1PTypes
open X509Basics
open X509Extensions


(***********************)
(* tbs and Certificate *)
(***********************)

asn1_alias issuerUniqueId = primitive [C_ContextSpecific, 1] der_bitstring
asn1_alias subjectUniqueId = primitive [C_ContextSpecific, 2] der_bitstring

struct tbsCertificate_content = {
  optional version : asn1 [(C_ContextSpecific, true, T_Unknown 0)] of der_smallint;
  serialNumber : der_integer;
  signature : algorithmIdentifier;
  parse_checkpoint position_before_issuer : save_offset;
  issuer : distinguishedName;
  parse_field issuer_raw : raw_value(position_before_issuer);
  validity : validity;
  parse_checkpoint position_before_subject : save_offset;
  subject : distinguishedName;
  parse_field subject_raw : raw_value(position_before_subject);
  subjectPublicKeyInfo : subjectPublicKeyInfo;
  optional issuerUniqueId : asn1 [(C_ContextSpecific, false, T_Unknown 1)] of der_bitstring_content;
  optional subjectUniqueId : asn1 [(C_ContextSpecific, false, T_Unknown 2)] of der_bitstring_content;
  optional extensions : asn1 [(C_ContextSpecific, true, T_Unknown 3)] of extension_list
}
asn1_alias tbsCertificate

struct certificate_content = {
  parse_checkpoint position_before_tbs : save_offset;
  tbsCertificate : tbsCertificate;
  parse_field tbsCertificate_raw : raw_value(position_before_tbs);
  signatureAlgorithm : algorithmIdentifier;
  parse_checkpoint _constraint : both_equal(false; (CustomException "signature algos should be equal");
                                            tbsCertificate.signature; signatureAlgorithm);
  signatureValue : bitstring_container of signature(signatureType_of_algo signatureAlgorithm)
}
asn1_alias certificate [top]




(**************************)
(* Populating directories *)
(**************************)

let attribute_value_types = [
  [85; 4; 41], "name", None, AVT_DirectoryString(AtMost 32768);
  [85; 4; 4], "surname", None, AVT_DirectoryString(AtMost 32768);
  [85; 4; 42], "givenName", None, AVT_DirectoryString(AtMost 32768);
  [85; 4; 43], "initials", None, AVT_DirectoryString(AtMost 32768);
  [85; 4; 44], "generationQualifier", None, AVT_DirectoryString(AtMost 32768);

  [85; 4; 3], "commonName", Some "CN", AVT_DirectoryString(AtMost 64);
  [85; 4; 7], "localityName", Some "L", AVT_DirectoryString(AtMost 128);
  [85; 4; 8], "stateOrProvinceName", Some "S", AVT_DirectoryString(AtMost 128);
  [85; 4; 10], "organizationName", Some "O", AVT_DirectoryString(AtMost 64);
  [85; 4; 11], "organizationalUnitName", Some "OU", AVT_DirectoryString(AtMost 64);
  [85; 4; 12], "title", None, AVT_DirectoryString(AtMost 64);
  [85; 4; 46], "dnQualifier", None, AVT_PrintableString(NoConstraint);
  [85; 4; 6], "countryName", Some "C", AVT_PrintableString(AtMost 2);
  [85; 4; 5], "serialNumber", Some "SN", AVT_PrintableString(AtMost 64);
  [85; 4; 65], "pseudonym", None, AVT_DirectoryString(AtMost 128);

  [9; 2342; 19200300; 100; 1; 25], "domainComponent", Some "dc", AVT_IA5String(NoConstraint);
  [42;840;113549;1;9;1], "emailAddress", None, AVT_IA5String(AtMost 255)
]


let dsa_spk_of_param = function
  | Some (DSAParams dp) -> SPK_DSA dp
  | _ -> SPK_Unknown

let public_key_types = [
  [42;840;113549;1;1;1], "rsaEncryption", APT_Null, (fun _ -> SPK_RSA);
  [42;840;10040;4;1], "dsa", APT_DSAParams, dsa_spk_of_param
]

let signature_types = [
  [42;840;113549;1;1;2], "md2WithRSAEncryption", APT_Null, (fun _ -> ST_RSA);
  [42;840;113549;1;1;3], "md4WithRSAEncryption", APT_Null, (fun _ -> ST_RSA);
  [42;840;113549;1;1;4], "md5WithRSAEncryption", APT_Null, (fun _ -> ST_RSA);
  [42;840;113549;1;1;5], "sha1WithRSAEncryption", APT_Null, (fun _ -> ST_RSA);
  [42;840;113549;1;1;11], "sha256WithRSAEncryption", APT_Null, (fun _ -> ST_RSA);
  [42;840;113549;1;1;12], "sha384WithRSAEncryption", APT_Null, (fun _ -> ST_RSA);
  [42;840;113549;1;1;13], "sha512WithRSAEncryption", APT_Null, (fun _ -> ST_RSA);
  [42;840;113549;1;1;14], "sha224WithRSAEncryption", APT_Null, (fun _ -> ST_RSA);
  [42;840;10040;4;3], "dsaWithSha1", APT_Null, (fun _ -> ST_DSA);
  [43;14;3;2;29], "sha1WithRSAEncryption", APT_Null, (fun _ -> ST_RSA);
  [96;840;1;101;3;4;3;1], "dsaWithSha224", APT_Null, (fun _ -> ST_DSA);
  [96;840;1;101;3;4;3;2], "dsaWithSha256", APT_Null, (fun _ -> ST_DSA);
]

let extension_types = [
  [85;29;1], "authorityKeyIdentifier"; (* Deprecated *)
  [85;29;14], "subjectKeyIdentifier";
  [85;29;15], "keyUsage";
  [85;29;16], "privateKeyUsagePeriod";
  [85;29;17], "subjectAltName";
  [85;29;18], "issuerAltName";
  [85;29;19], "basicConstraints";
  [85;29;30], "nameConstraints";
  [85;29;31], "crlDistributionPoints";
  [85;29;32], "certificatePolicies";
  [85;29;35], "authorityKeyIdentifier";
  [85;29;37], "extendedKeyUsage";
  [43;6;1;5;5;7;1;1], "authorityInfoAccess";
  [96;840;1;113730;1;1], "nsCertType";
  [96;840;1;113730;1;13], "nsComment"
]


let other_oids = [
  (* Prefixes *)
  [43;6;1;5;5;7], "id-pkix";
  [43;6;1;5;5;7;1], "id-pe";
  [43;6;1;5;5;7;2], "id-qt";
  [43;6;1;5;5;7;3], "id-kp";
  [43;6;1;5;5;7;48], "id-ad";
  [85;29], "id-ce";

  [85;29;37;0], "anyExtendedKeyUsage";
  [43;6;1;5;5;7;3;1], "serverAuth";
  [43;6;1;5;5;7;3;2], "clientAuth";
  [43;6;1;5;5;7;3;3], "codeSigning";
  [43;6;1;5;5;7;3;4], "emailProtection";
  [43;6;1;5;5;7;3;8], "timeStamping";
  [43;6;1;5;5;7;3;9], "OCSPSigning";

  [85;29;32;0], "anyPolicy";
  [43;6;1;5;5;7;2;1], "id-qt-cps";
  [43;6;1;5;5;7;2;2], "id-qt-unotice";

  [43;6;1;5;5;7;48;1], "id-ad-ocsp";
  [43;6;1;5;5;7;48;2], "id-ad-caIssuers";
]


let _ =
  List.iter (populate_atv_directory) attribute_value_types;
  List.iter (fun (id, name) -> register_oid id name) extension_types;
  List.iter (fun (id, name) -> register_oid id name) other_oids;
  List.iter (populate_alg_directory subjectPublicKeyType_directory) public_key_types;
  List.iter (populate_alg_directory signatureType_directory) signature_types;  
  ()


