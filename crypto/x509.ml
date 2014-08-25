open Parsifal
open PTypes
open Asn1Engine
open Asn1PTypes
open X509Basics
open X509Extensions


(************************)
(* SubjectPublicKeyInfo *)
(************************)

type subjectPublicKeyType =
  | SPK_DSA of DSAKey.dsa_params
  | SPK_DH of DHKey.dh_params
  | SPK_RSA
  | SPK_Unknown

let subjectPublicKeyType_directory : (int list, algorithmParams option -> subjectPublicKeyType) Hashtbl.t = Hashtbl.create 10
let subjectPublicKeyType_of_algo algo =
  try
    let f = Hashtbl.find subjectPublicKeyType_directory algo.algorithmId in
    f algo.algorithmParams
  with Not_found -> SPK_Unknown

union subjectPublicKey [enrich] (UnparsedPublicKey of binstring) =
  | SPK_DSA _params -> DSA of DSAKey.dsa_public_key
  | SPK_DH _params -> DH of DHKey.dh_public_key
  | SPK_RSA -> RSA of Pkcs1.rsa_public_key

asn1_struct subjectPublicKeyInfo = {
  algorithm : algorithmIdentifier;
  subjectPublicKey : bitstring_container of subjectPublicKey(subjectPublicKeyType_of_algo algorithm)
}



(*************)
(* Signature *)
(*************)

type signatureType =
  | ST_DSA
  | ST_RSA
  | ST_Unknown

let signatureType_directory : (int list, algorithmParams option -> signatureType) Hashtbl.t = Hashtbl.create 10
let signatureType_of_algo algo =
  try
    let f = Hashtbl.find signatureType_directory algo.algorithmId in
    f algo.algorithmParams
  with Not_found -> ST_Unknown

union signature [enrich] (UnparsedSignature of binstring) =
  | ST_DSA -> DSASignature of DSAKey.dsa_signature
  | ST_RSA -> RSASignature of Pkcs1.rsa_signature



(***********************)
(* tbs and Certificate *)
(***********************)

asn1_alias issuerUniqueId = primitive [C_ContextSpecific, 1] der_bitstring
asn1_alias subjectUniqueId = primitive [C_ContextSpecific, 2] der_bitstring

asn1_struct tbsCertificate = {
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

struct certificate_content = {
  parse_checkpoint position_before_tbs : save_offset;
  tbsCertificate : tbsCertificate;
  parse_field tbsCertificate_raw : raw_value(position_before_tbs);
  signatureAlgorithm : algorithmIdentifier;
  parse_checkpoint : both_equal(false; (CustomException "signature algos should be equal");
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

let dh_spk_of_param = function
  | Some (DHParams dp) -> SPK_DH dp
  | _ -> SPK_Unknown

let public_key_types = [
  [42;840;113549;1;1;1], "rsaEncryption", APT_Null, (fun _ -> SPK_RSA);
  [42;840;10040;4;1], "dsa", APT_DSAParams, dsa_spk_of_param;
  [42;840;10046;2;1], "dh-public-number" , APT_DHParams, dh_spk_of_param;
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

let capability_types = [
  [42;840;113549;3;2], "rc2-cbc", CT_Int;
  [42;840;113549;3;4], "rc4", CT_Int;
  [42;840;113549;3;7], "des-ede3-cbc", CT_Null;
  [43;14;3;2;7], "desCBC", CT_Null;
  [96;840;1;101;3;4;1;42], "aes256-CBC", CT_Null;
  [96;840;1;101;3;4;1;45], "id-aes256-wrap", CT_Null;
  [96;840;1;101;3;4;1;2], "aes128-CBC", CT_Null;
  [96;840;1;101;3;4;1;5], "id-aes128-wrap", CT_Null;
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
  [85;29;46], "freshestCRL";
  [43;6;1;5;5;7;1;1], "authorityInfoAccess";
  [43;6;1;5;5;7;1;12], "logotype";
  [96;840;1;113730;1;1], "nsCertType";
  [96;840;1;113730;1;2], "nsBaseURL";
  [96;840;1;113730;1;3], "nsRevocationURL";
  [96;840;1;113730;1;4], "nsCARevocationURL";
  [96;840;1;113730;1;7], "nsRenewalURL";
  [96;840;1;113730;1;8], "nsCAPolicyURL";
  [96;840;1;113730;1;12], "nsSSLServerName";
  [96;840;1;113730;1;13], "nsComment";
  [42;840;113549;1;9;15], "sMIMECapabilities";
]


let other_oids = [
  (* Prefixes *)
  [43;6;1;5;2;2], "id-pkinit-san";
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
  List.iter populate_atv_directory attribute_value_types;
  List.iter populate_cap_directory capability_types;
  List.iter (fun (id, name) -> register_oid id name) extension_types;
  List.iter (fun (id, name) -> register_oid id name) other_oids;
  List.iter (populate_alg_directory subjectPublicKeyType_directory) public_key_types;
  List.iter (populate_alg_directory signatureType_directory) signature_types;  
  ()


let get_extn_by_id id c =
  match c.tbsCertificate.extensions with
  | None -> None
  | Some es ->
    match List.filter (fun e -> e.extnID = id) es with
    | [e] -> Some e.extnValue
    | [] -> None
    | _::_::_ ->
      failwith (Printf.sprintf "get_extn_by_id: Duplicate extension (%s)" (string_of_oid id))


let extract_dns_and_ips c =
  let san_oid = Hashtbl.find Asn1PTypes.rev_oid_directory "subjectAltName"
  and cn_oid = Hashtbl.find Asn1PTypes.rev_oid_directory "commonName" in

  let cns = List.map (fun atv -> "CN", string_of_atv_value atv.attributeValue)
    (List.filter (fun atv -> atv.attributeType = cn_oid) (List.flatten c.tbsCertificate.subject))
  in

  let sans =
    match get_extn_by_id san_oid c with
    | Some (X509Extensions.SubjectAltName gns) ->
      let rec extract_dns_or_ip = function
	| [] -> []
	| (X509Extensions.DNSName s)::r ->
	  ("DNS", s)::(extract_dns_or_ip r)
	| (X509Extensions.IPAddress s)::r ->
	  let ip = if String.length s = 4 then string_of_ipv4 s else hexdump s in
	  ("IP", ip)::(extract_dns_or_ip r)
	| _::r -> extract_dns_or_ip r
      in
      extract_dns_or_ip gns
    | _ -> []
  in
  cns@sans
