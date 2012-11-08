open Parsifal
open Asn1Engine
open Asn1PTypes


struct certId_content = {
  hashAlgorithm : X509.algorithmIdentifier;
  issuerNameHash : der_octetstring;
  issuerKeyHash : der_octetstring;
  serialNumber : der_integer
}
asn1_alias certId

struct request_content = {
  reqCert : certId;
  optional singleRequestExtensions : asn1 [(C_ContextSpecific, true, T_Unknown 0)] of X509.extension_list
}
asn1_alias request
asn1_alias request_list = seq_of request

struct signature_content = {
  signatureAlgorithm : X509.algorithmIdentifier;
  signature : der_bitstring;
  optional certs : asn1 [(C_ContextSpecific, true, T_Unknown 0)] of asn1 [(C_Universal, true, T_Sequence)] of X509.certificate
}
asn1_alias signature


struct tbsRequest_content = {
  optional version : asn1 [(C_ContextSpecific, true, T_Unknown 0)] of der_smallint;
  optional requestorName : asn1 [(C_ContextSpecific, true, T_Unknown 1)] of der_object; (* TODO *)    
  requestList : request_list;
  optional requestExtensions : asn1 [(C_ContextSpecific, true, T_Unknown 2)] of X509.extension_list
}  
asn1_alias tbsRequest


struct ocspRequest_content = {
  tbsRequest : tbsRequest;
  optionalSignature : asn1 [(C_ContextSpecific, true, T_Unknown 0)] of signature
}
asn1_alias ocspRequest




struct responseBytes_content = {
  responseType : der_oid;
  response : der_octetstring
}
asn1_alias responseBytes
   (* For a basic OCSP responder, responseType will be id-pkix-ocsp-basic. *)
   (* id-pkix-ocsp           OBJECT IDENTIFIER ::= { id-ad-ocsp } *)
   (* id-pkix-ocsp-basic     OBJECT IDENTIFIER ::= { id-pkix-ocsp 1 } *)


alias ocspResponseStatus = der_object
   (* OCSPResponseStatus ::= ENUMERATED { *)
   (*     successful            (0),  --Response has valid confirmations *)
   (*     malformedRequest      (1),  --Illegal confirmation request *)
   (*     internalError         (2),  --Internal error in issuer *)
   (*     tryLater              (3),  --Try again later *)
   (*                                 --(4) is not used *)
   (*     sigRequired           (5),  --Must sign the request *)
   (*     unauthorized          (6)   --Request unauthorized *)
   (* } *)

struct ocspResponse_content = {
  responseStatus : ocspResponseStatus;
  optional responseBytes : asn1 [(C_ContextSpecific, true, T_Unknown 0)] of responseBytes
}
asn1_alias ocspResponse





   (* The value for response SHALL be the DER encoding of *)
   (* BasicOCSPResponse. *)

   (* BasicOCSPResponse       ::= SEQUENCE { *)
   (*    tbsResponseData      ResponseData, *)
   (*    signatureAlgorithm   AlgorithmIdentifier, *)
   (*    signature            BIT STRING, *)
   (*    certs                [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL } *)

   (* The value for signature SHALL be computed on the hash of the DER *)
   (* encoding ResponseData. *)

   (* ResponseData ::= SEQUENCE { *)
   (*    version              [0] EXPLICIT Version DEFAULT v1, *)
   (*    responderID              ResponderID, *)
   (*    producedAt               GeneralizedTime, *)
   (*    responses                SEQUENCE OF SingleResponse, *)
   (*    responseExtensions   [1] EXPLICIT Extensions OPTIONAL } *)

   (* ResponderID ::= CHOICE { *)
   (*    byName               [1] Name, *)
   (*    byKey                [2] KeyHash } *)

   (* KeyHash ::= OCTET STRING -- SHA-1 hash of responder's public key *)
   (* (excluding the tag and length fields) *)

   (* SingleResponse ::= SEQUENCE { *)
   (*    certID                       CertID, *)
   (*    certStatus                   CertStatus, *)
   (*    thisUpdate                   GeneralizedTime, *)
   (*    nextUpdate         [0]       EXPLICIT GeneralizedTime OPTIONAL, *)
   (*    singleExtensions   [1]       EXPLICIT Extensions OPTIONAL } *)

   (* CertStatus ::= CHOICE { *)
   (*     good        [0]     IMPLICIT NULL, *)
   (*     revoked     [1]     IMPLICIT RevokedInfo, *)
   (*     unknown     [2]     IMPLICIT UnknownInfo } *)

   (* RevokedInfo ::= SEQUENCE { *)
   (*     revocationTime              GeneralizedTime, *)
   (*     revocationReason    [0]     EXPLICIT CRLReason OPTIONAL } *)

   (* UnknownInfo ::= NULL -- this can be replaced with an enumeration *)
