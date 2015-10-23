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
  | SPK_EC of ECKey.ec_params
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
  | SPK_EC _params -> EC of ECKey.ec_public_key

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
  | ST_ECDSA
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
  | ST_ECDSA -> ECDSASignature of ECKey.ecdsa_signature


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

let ec_spk_of_param = function
  | Some (ECParams ecp) -> SPK_EC ecp
  | _ -> SPK_Unknown

let public_key_types = [
  [42;840;113549;1;1;1], "rsaEncryption", APT_Null, (fun _ -> SPK_RSA);
  [42;840;10040;4;1], "dsa", APT_DSAParams, dsa_spk_of_param;
  [42;840;10046;2;1], "dh-public-number" , APT_DHParams, dh_spk_of_param;
  [42;840;10045;2;1], "ecPublicKey", APT_ECParams, ec_spk_of_param;
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
  [42;840;10045;4;3;3], "ecdsaWithSha384", APT_Null, (fun _ -> ST_ECDSA);
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
  authorityKeyIdentifier_deprecated_oid, "authorityKeyIdentifier"; (* Deprecated *)
  subjectKeyIdentifier_oid, "subjectKeyIdentifier";
  keyUsage_oid, "keyUsage";
  privateKeyUsagePeriod_oid, "privateKeyUsagePeriod";
  subjectAltName_oid, "subjectAltName";
  issuerAltName_oid, "issuerAltName";
  basicConstraints_oid, "basicConstraints";
  nameConstraints_oid, "nameConstraints";
  crlDistributionPoints_oid, "crlDistributionPoints";
  certificatePolicies_oid, "certificatePolicies";
  policyMappings_oid, "policyMappings";
  authorityKeyIdentifier_oid, "authorityKeyIdentifier";
  extendedKeyUsage_oid, "extendedKeyUsage";
  freshestCRL_oid, "freshestCRL";
  authorityInfoAccess_oid, "authorityInfoAccess";
  logotype_oid, "logotype";
  nsCertType_oid, "nsCertType";
  nsBaseURL_oid, "nsBaseURL";
  nsRevocationURL_oid, "nsRevocationURL";
  nsCARevocationURL_oid, "nsCARevocationURL";
  nsRenewalURL_oid, "nsRenewalURL";
  nsCAPolicyURL_oid, "nsCAPolicyURL";
  nsSSLServerName_oid, "nsSSLServerName";
  nsComment_oid, "nsComment";
  sMIMECapabilities_oid, "sMIMECapabilities";
]


(* TODO: Add _oid constants *)

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

  [43;132;0;1], "sect163k1";
  [43;132;0;2], "sect163r1";
  [43;132;0;3], "sect239k1";
  [43;132;0;4], "sect113r1";
  [43;132;0;5], "sect113r2";
  [43;132;0;6], "secp112r1";
  [43;132;0;7], "secp112r2";
  [43;132;0;8], "secp160r1";
  [43;132;0;9], "secp160k1";
  [43;132;0;10], "secp256k1";
  [43;132;0;15], "sect163r2";
  [43;132;0;16], "sect283k1";
  [43;132;0;17], "sect283r1";
  [43;132;0;22], "sect131r1";
  [43;132;0;24], "sect193r1";
  [43;132;0;25], "sect193r2";
  [43;132;0;26], "sect233k1";
  [43;132;0;27], "sect233r1";
  [43;132;0;28], "secp128r1";
  [43;132;0;29], "secp128r2";
  [43;132;0;30], "secp160r2";
  [43;132;0;31], "secp192k1";
  [43;132;0;32], "secp224k1";
  [43;132;0;33], "secp224r1";
  [43;132;0;34], "secp384r1";
  [43;132;0;35], "secp521r1";
  [43;132;0;36], "sect409k1";
  [43;132;0;37], "sect409r1";
  [43;132;0;38], "sect571k1";
  [43;132;0;39], "sect571r1";
]


let _ =
  List.iter populate_atv_directory attribute_value_types;
  List.iter populate_cap_directory capability_types;
  List.iter (fun (id, name) -> register_oid id name) extension_types;
  List.iter (fun (id, name) -> register_oid id name) other_oids;
  List.iter (populate_alg_directory subjectPublicKeyType_directory) public_key_types;
  List.iter (populate_alg_directory signatureType_directory) signature_types;  
  ()


let accept_x509_identical_extensions = ref false

let get_extn_by_id id extensions =
  match extensions with
  | None -> None
  | Some es ->
    match List.filter (fun e -> e.extnID = id) es with
    | [e] -> Some (e.extnValue, e.critical)
    | [] -> None
    | e::es ->
      if !accept_x509_identical_extensions then begin
        let rec all_equal reference = function
          | [] -> true
          | x::xs -> x = reference && all_equal reference xs
        in
        if all_equal e es
        then Some (e.extnValue, e.critical) (* TODO: This should be a warning... We are a bit laxist *)
        else failwith (Printf.sprintf "get_extn_by_id: Duplicate (and different) extensions (%s)" (string_of_oid id))
      end else failwith (Printf.sprintf "get_extn_by_id: Duplicate extension (%s)" (string_of_oid id))

let extract_dns_and_ips c =
  let cn_oid = Hashtbl.find Asn1PTypes.rev_oid_directory "commonName" in

  let cns = List.map (fun atv -> "CN", string_of_atv_value atv.attributeValue)
    (List.filter (fun atv -> atv.attributeType = cn_oid) (List.flatten c.tbsCertificate.subject))
  in

  let sans =
    match get_extn_by_id subjectAltName_oid c.tbsCertificate.extensions with
    | Some (X509Extensions.SubjectAltName gns, _) ->
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
