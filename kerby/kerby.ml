open Parsifal
open PTypes
open Asn1PTypes
open Asn1Engine
open X509Basics
open Padata
open KerberosTypes

let dest_port = ref 88

(* NOT USED *)
enum padata_type (8, UnknownVal UnknownPreAuthenticationType) =
  | 1 -> PA_TGS_REQ
  | 2 -> PA_ENC_TIMESTAMP
  | 3 -> PA_PW_SALT (* NOT ASN.1 ENCODED !*)
  | 11 -> PA_ETYPE_INFO
  | 16 -> PA_PK_AS_REQ
  | 17 -> PA_PK_AS_REP
  | 18 -> PA_ETYPE_INFO_UNUSUED
  | 19 -> PA_ETYPE_INFO2

(*
asn1_alias padata_value
*)

(* Tentative pour utiliser l'enum padata_type *)
(*
let parse_asn1_enum parse_fun input =
  let v = parse_der_integer input in
  let new_input = input_of_string "asn1_enum" v in
  parse_fun new_input

let dump_asn1_enum _dump_fun _buf _enum = raise (ParsingException (NotImplemented "dump_asn1_enum", []))
*)

struct padata_content =
{
  (*
  padata_type : cspe [1] of asn1 [(C_Universal, false, T_Integer)] of padata_type; (* WRONG because type may be > 128 *)
  padata_type : cspe [1] of asn1_enum of padata_type (* WRONG because it is 4 bytes long *)
  *)
  (* We stick with der_smallint for now *)
  padata_type : cspe [1] of der_smallint;
  optional padata_value : cspe [2] of octetstring_container of padata_value(padata_type, true)
}
asn1_alias padata
asn1_alias padatas = seq_of padata

struct err_padata_content =
{
  (* We stick with der_smallint for now *)
  padata_type :  cspe[1] of der_smallint;
  (* Passing "false" to discriminate the error_msg case where padata_value will be NULL *)
  optional padata_value : cspe [2] of octetstring_container of padata_value(padata_type, false)
}
asn1_alias err_padata
asn1_alias err_padatas = seq_of err_padata

(* FIXME !!
asn1_alias etypes = seq_of asn1 [(C_Universal, false, T_Integer)] of etype_type
*)
asn1_alias etypes = seq_of der_integer

struct req_body_content =
{
  kdc_options: 		cspe [0] of der_enumerated_bitstring[kdc_options_values];
  optional cname: 	cspe [1] of cname; 			(* PrincipalName, Used only in AS-REQ *) 
  realm : 		cspe [2] of der_kerberos_string; 	(* Realm *)
  optional sname : 	cspe [3] of sname; 			(* PrincipalName OPTIONAL,*)
  optional from : 	cspe [4] of der_kerberos_time; 		(* KerberosTime OPTIONAL,*)
  till : 		cspe [5] of der_kerberos_time; 		(* KerberosTime *)
  optional time : 	cspe [6] of der_kerberos_time; 		(* KerberosTime OPTIONAL,*)
  nonce : 		cspe [7] of der_smallint; 		(* UInt32 *)
  etype : 		cspe [8] of etypes; 			(* SEQUENCE OF Int32  -- EncryptionType*)
  optional addresses: 	cspe [9] of host_addresses; 		(* HostAddresses OPTIONAL,*)
  optional enc_authorization_data: 	cspe [10] of encrypted_data;	(* EncryptedData OPTIONAL*)
  optional additional_tickets: 		cspe [11] of der_object		(* SEQUENCE OF Ticket OPTIONAL *)
}

(*alias req_body = der_object*)
asn1_alias req_body

(* NOT USED NOW BECAUSE WE CANNOT DECIPHER WITHOUT KEYS *)
(*
struct enc_ticket_part_content = 
{
  flags : cspe [0] of binstring;
  key : cspe [1] of binstring;
  crealm : cspe [2] of binstring;
  cname : cspe [3] of binstring;
  transited : cspe [4] of binstring;
  authtime : cspe [5] of binstring;
  optional starttime : cspe [6] of binstring;
  endtime : cspe [7] of binstring;
  optional renew_till : cspe [8] of binstring;
  optional caddr : cspe [9] of binstring;
  optional authorization_data : cspe [10] of binstring;
}
asn1_alias enc_ticket_part
*)

(* AP_REQ *)
(* defined in PADATA, because it can be used in PA_TGS_REQ *)

(* AP_REP *)
asn1_struct ap_rep =
{
  pvno : 	cspe [0] of asn1 [(C_Universal, false, T_Integer)] of pvno;
  msg_type : 	cspe [1] of asn1 [(C_Universal, false, T_Integer)] of msg_type;
  enc_part : 	cspe [2] of encrypted_data
}

(* AS_REQ *)
asn1_struct as_req =
{
  pvno : 	cspe [1] of asn1 [(C_Universal, false, T_Integer)] of pvno;
  msg_type : 	cspe [2] of asn1 [(C_Universal, false, T_Integer)] of msg_type;
  optional padata : cspe [3] of padatas;
  req_body : 	cspe [4] of req_body;
}

(* AS_REP *)
asn1_struct as_rep =
{
  pvno : 	cspe [0] of asn1 [(C_Universal, false, T_Integer)] of pvno;
  msg_type : 	cspe [1] of asn1 [(C_Universal, false, T_Integer)] of msg_type;
  optional padata : cspe [2] of padatas;
  crealm : 	cspe [3] of der_kerberos_string;
  cname : 	cspe [4] of cname;
  ticket : 	cspe [5] of asn1 [(C_Application, true, T_Unknown 1)] of ticket;
  enc_part : 	cspe [6] of encrypted_data
}

(* KRB_ERR *)
asn1_struct krb_error = {
  pvno : 	cspe [0] of asn1 [(C_Universal, false, T_Integer)] of pvno;
  msg_type : 	cspe [1] of asn1 [(C_Universal, false, T_Integer)] of msg_type;
  optional ctime : 	cspe [2] of der_kerberos_time;
  optional cusec : 	cspe [3] of binstring;
  stime : 	cspe [4] of der_kerberos_time;
  optional susec : 	cspe [5] of binstring;
  error_code : 	cspe [6] of der_smallint;
  optional crealm : 	cspe [7] of der_kerberos_string;
  optional cname : 	cspe [8] of cname;
  realm : 	cspe [9] of der_kerberos_string;
  sname : 	cspe [10] of sname;
  optional e_text : 	cspe [11] of der_kerberos_string;
  optional e_data : 	cspe [12] of octetstring_container of err_padatas
}

asn1_union kerberos_msg_type [enrich] (UnparsedKerberosMessage ) =
  | (C_Application, true, T_Unknown 10) -> AS_REQ of as_req
  | (C_Application, true, T_Unknown 11) -> AS_REP of as_rep
  | (C_Application, true, T_Unknown 12) -> TGS_REQ of as_req
  | (C_Application, true, T_Unknown 13) -> TGS_REP of as_rep
  | (C_Application, true, T_Unknown 14) -> AP_REQ of ap_req
  | (C_Application, true, T_Unknown 15) -> AP_REP of ap_rep
  | (C_Application, true, T_Unknown 30) -> KRB_ERR of krb_error

struct kerberos_msg = 
{
  record_mark : binstring(4);
  msg_content : kerberos_msg_type;
}

struct kerberos_udp_msg = 
{
  msg_content : kerberos_msg_type;
}
