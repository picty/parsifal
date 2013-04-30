open Lwt
open Parsifal
open PTypes
open Pcap
open Asn1PTypes
open Asn1Engine
open X509Basics
open Padata
open Getopt



let dest_port = ref 88


type direction = ServerToClient | ClientToServer
let string_of_dir = function ServerToClient -> "S->C" | ClientToServer -> "C->S"

type connection_key = {
  source : ipv4 * int;
  destination : ipv4 * int;
}
    
type segment = direction * int * string

type connection = {
  first_src_seq : int;
  first_dst_seq : int;
  segments : segment list
}

let connections : (connection_key, connection) Hashtbl.t = Hashtbl.create 100


let update_connection = function
  | { ip_payload = TCPLayer {
    tcp_payload = "" } } -> ()
    (* TODO: Handle SYN/SYN-ACK *)

  | { source_ip = src_ip;
      dest_ip = dst_ip;
      ip_payload = TCPLayer {
	source_port = src_port;
	dest_port = dst_port;
	seq = seq; ack = ack;
	tcp_payload = payload } } ->
    begin
      let key, src_seq, dst_seq, dir =
	if dst_port = !dest_port
	then Some {source = src_ip, src_port;
		   destination = dst_ip, dst_port},
	  seq, ack, ClientToServer
	else if src_port = !dest_port
	then Some {source = dst_ip, dst_port;
		   destination = src_ip, src_port},
	   ack, seq, ServerToClient
	else None, 0, 0, ClientToServer
      in match key with
      | None -> ()
      | Some k -> begin
	try
	  let c = Hashtbl.find connections k in
	  (* TODO: We do NOT handle seq wrapping *)
	  Hashtbl.replace connections k {
	    first_src_seq = min c.first_src_seq src_seq;
	    first_dst_seq = min c.first_dst_seq dst_seq;
	    segments = c.segments@[dir, src_seq, payload]
	  }
	with Not_found ->
	  Hashtbl.replace connections k {
	    first_src_seq = src_seq;
	    first_dst_seq = dst_seq;
	  segments = [dir, src_seq, payload]
	  }
      end
    end
  | _ -> ()


enum msg_type (8, UnknownVal UnknownMsgType) =
  | 10 -> AS_REQ
  | 11 -> AS_REP
  | 12 -> TGS_REQ
  | 13 -> TGS_REP
  | 30 -> KRB_ERROR

enum pvno (8, UnknownVal UnknownProtocolVersion) =
  | 5 -> KerberosV5

enum padata_type (8, UnknownVal UnknownPreAuthenticationType) =
  | 1 -> PA_TGS_REQ
  | 2 -> PA_ENC_TIMESTAMP
  | 3 -> PA_PW_SALT (* NOT ASN.1 ENCODED !*)
  | 11 -> PA_ETYPE_INFO
  | 16 -> PA_PK_AS_REQ
  | 17 -> PA_PK_AS_REP
  | 18 -> PA_ETYPE_INFO
  | 19 -> PA_ETYPE_INFO2

enum principalname_type (8, UnknownVal UnknownPrincipalNameType) =
  | 1 -> Principal
  | 2 -> Service_and_Instance
  | 3 -> Service_and_Host

(* ContextSpecific optimization *)
let parse_cspe n parse_fun input = parse_asn1 (C_ContextSpecific, true, T_Unknown n) parse_fun input
let dump_cspe n dump_fun buf o = dump_asn1 (C_ContextSpecific, true, T_Unknown n) dump_fun buf o

union padata_value [enrich] (UnparsedPaDataValueContent of binstring) =
  | 1, true -> PA_TGS_REQ of binstring
  | 2, true -> PA_ENC_TIMESTAMP of binstring
  | 14, true -> PA_PK_AS_REQ_OLD of binstring
  | 15, true -> PA_PK_AS_REP_OLD of binstring
  | 16, true -> PA_PK_AS_REQ of pa_pk_as_req (* FIXME Improve PKCS7 *)
  | 17, true -> PA_PK_AS_REP of pa_pk_as_rep (* TODO PKCS7 *)
  | 18, true -> PA_ENCTYPE_INFO of binstring
  | 19,  _ -> PA_ENCTYPE_INFO2 of etype_info2s
  | 133, _ -> Other_PA_DATA of string 		(* TODO Is it MIT only ? *)
  | 136, true -> Other_PA_DATA of binstring
  | 147, true -> Other_PA_DATA of binstring
  | 149, true -> Other_PA_DATA of binstring
  | _, false -> PA_NULL of binstring

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

struct cname_content =
{
  (*name_type : cspe [0] of der_smallint;*)
  name_type :   cspe [0] of asn1 [(C_Universal, false, T_Integer)] of principalname_type;
  name_string : cspe [1] of seqkerbstring
}
asn1_alias cname
alias sname = cname
asn1_alias etypes = seq_of asn1 [(C_Universal, false, T_Integer)] of etype_type

let kdc_options_values = [|
  "RESERVED";
  "FORWARDABLE";
  "FORWARDED";
  "PROXIABLE";
  "PROXY";
  "ALLOW_POSTDATE";
  "POSTDATED";
  "RESERVED";
  "RENEWABLE";
  "RESERVED";
  "RESERVED";
  "RESERVED_OPT_HW_AUTH";
  "RESERVED";
  "RESERVED";
  "RESERVED_CONSTRAINED_DELEGATION";
  "RESERVED_CANONICALIZE";
  "RESERVED";
  "RESERVED";
  "RESERVED";
  "RESERVED";
  "RESERVED";
  "RESERVED";
  "RESERVED";
  "RESERVED";
  "RESERVED";
  "RESERVED";
  "DISABLE_TRANSITED_CHECK";
  "RENEWABLE_OK";
  "ENC_TKT_IN_SKEY";
  "RESERVED";
  "RENEW";
  "VALIDATE"
|]

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
  optional addresses: 	cspe [9] of der_object; 		(* HostAddresses OPTIONAL,*)
  optional enc_authorization_data: 	cspe [10] of der_object;	(* EncryptedData OPTIONAL*)
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

struct encrypted_data_content = 
{
  encryption_type : 	cspe [0] of asn1 [(C_Universal, false, T_Integer)] of etype_type;
  kvno : 		cspe [1] of der_smallint;
  cipher : 		cspe [2] of binstring
}
asn1_alias encrypted_data

struct ticket_content =
{
  tkvno : cspe [0] of der_smallint;
  realm : cspe [1] of der_kerberos_string;
  sname : cspe [2] of sname;
  enc_tkt_part : cspe [3] of encrypted_data;
}
asn1_alias ticket

struct as_req_content =
{
  pvno : 	cspe [1] of asn1 [(C_Universal, false, T_Integer)] of pvno;
  msg_type : 	cspe [2] of asn1 [(C_Universal, false, T_Integer)] of msg_type;
  optional padata : cspe [3] of padatas;
  req_body : 	cspe [4] of req_body;
}
asn1_alias as_req

struct as_rep_content =
{
  pvno : 	cspe [0] of asn1 [(C_Universal, false, T_Integer)] of pvno;
  msg_type : 	cspe [1] of asn1 [(C_Universal, false, T_Integer)] of msg_type;
  optional padata : cspe [2] of padatas;
  crealm : 	cspe [3] of der_kerberos_string;
  cname : 	cspe [4] of cname;
  ticket : 	cspe [5] of asn1 [(C_Application, true, T_Unknown 1)] of ticket;
  enc_part : 	cspe [6] of binstring;
}
asn1_alias as_rep


struct krb_error_content = {
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
asn1_alias krb_error

asn1_union kerberos_msg_type [enrich] (UnparsedKerberosMessage ) =
  | (C_Application, true, T_Unknown 10) -> AS_REQ of as_req
  | (C_Application, true, T_Unknown 11) -> AS_REP of as_rep
  | (C_Application, true, T_Unknown 12) -> TGS_REQ of as_req
  | (C_Application, true, T_Unknown 13) -> TGS_REP of as_rep
  | (C_Application, true, T_Unknown 30) -> KRB_ERR of krb_error

struct kerberos_msg = 
{
  record_mark : binstring(4);
  msg_content : kerberos_msg_type;
}

let handle_connection k c =
  let rec trivial_aggregate = function
    | [] -> []
    | (dir, _, seg)::ss ->
      match trivial_aggregate ss with
      | [] -> [dir, seg]
      | ((dir', seg')::r) as l ->
	if (dir = dir')
	then (dir, seg ^ seg')::r
	else (dir, seg)::l
  in

  let cname = Printf.sprintf "%s:%d -> %s:%d\n"
    (string_of_ipv4 (fst k.source)) (snd k.source)
    (string_of_ipv4 (fst k.destination)) (snd k.destination)
  in

(*
  print_endline cname;
  let segs = String.concat "" (List.map snd (trivial_aggregate c.segments)) in
  let records, _ = parse_all_records !enrich_style (input_of_string cname segs) in
  List.iter (fun r -> print_endline (print_value ~verbose:!verbose ~indent:"  " (value_of_tls_record r))) records;
  print_newline ()
*)

  print_endline cname;
  (*
  let segs = String.concat "" (List.map snd (trivial_aggregate c.segments)) in
  *)
  let segs = trivial_aggregate c.segments in
  let handle_one_seg (dir, content) =
    let input = input_of_string "" content in
    let kerberos_msg = parse_kerberos_msg input in
    let str_value = print_value (value_of_kerberos_msg kerberos_msg) in
    Printf.printf "  %s : %s\n" (string_of_dir dir) str_value
  in
  List.iter handle_one_seg segs;
  print_newline ()

  (* Si tu as ecrit kerberos_msg, 
     let msg = parse_kerberos_msg (input_of_string (string_of_dir dir) content) *)
 (* List.iter (fun (dir, content) -> Printf.printf "  %s :\n" (string_of_dir dir) (parse_as_req content)) segs ;

  List.iter (fun (dir, content) -> Printf.printf "  %s : %s\n" (string_of_dir dir) (hexdump content)) segs ;
  print_newline () *)

let handle_one_packet packet = match packet.data with
  | EthernetContent { ether_payload = IPLayer ip_layer }
  | IPContent ip_layer ->
    update_connection ip_layer
  | _ -> ()

let handle_one_file input =
  lwt_parse_pcap_file input >>= fun pcap ->
  List.iter handle_one_packet pcap.packets;
  Hashtbl.iter handle_connection connections;

  return ()


let _ =
  try
    let args = parse_args ~progname:"extractSessions" [] Sys.argv in
    let open_files = function
      | [] -> input_of_channel "(stdin)" Lwt_io.stdin >>= fun x -> return [x]
      | _ -> Lwt_list.map_s input_of_filename args
    in
    Lwt_unix.run (open_files args >>= Lwt_list.iter_s handle_one_file);
  with
    | ParsingException (e, h) -> prerr_endline (string_of_exception e h); exit 1
    | e -> print_endline (Printexc.to_string e); exit 1
