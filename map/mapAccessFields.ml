open MapLang

let add_cert_field name f = Hashtbl.replace certificate_field_access name f
let add_answer_field name f = Hashtbl.replace answer_field_access name f
let add_tls_field name f = Hashtbl.replace tls_field_access name f
let add_dn_field name f = Hashtbl.replace dn_field_access name f
let add_asn1_field name f = Hashtbl.replace asn1_field_access name f

let _ =
  add_answer_field "ip" (fun x -> V_String (Common.string_of_ip x.AnswerDump.ip));
  add_answer_field "port" (fun x -> V_Int x.AnswerDump.port);
  add_answer_field "name" (fun x -> V_String x.AnswerDump.name);
  add_answer_field "client_hello_type" (fun x -> V_Int x.AnswerDump.client_hello_type);
  add_answer_field "msg_type" (fun x -> V_Int x.AnswerDump.msg_type);
  add_answer_field "content" (fun x -> V_String x.AnswerDump.content);

  add_cert_field "version" (fun x -> match x.X509.tbs.X509.version with None -> raise Not_found | Some v -> V_Int v);
  add_cert_field "serial" (fun x -> V_String (Common.hexdump_int_list x.X509.tbs.X509.serial));
  add_cert_field "issuer" (fun x -> V_DN (x.X509.tbs.X509.issuer));
  add_cert_field "notbefore" (fun x -> V_String (X509.string_of_datetime (x.X509.tbs.X509.validity.X509.not_before)));
  add_cert_field "notafter" (fun x -> V_String (X509.string_of_datetime (x.X509.tbs.X509.validity.X509.not_after)));
  add_cert_field "subject" (fun x -> V_DN (x.X509.tbs.X509.subject));
(* TODO:
type tbs_certificate = {
  sig_algo : oid_object;
  pk_info : public_key_info;
  issuer_unique_id : (int * string) option;
  subject_unique_id : (int * string) option;
  extensions : asn1_object option
}
*)

  add_tls_field "version" (fun x -> V_String (Tls.string_of_protocol_version x.Tls.version));
  add_tls_field "content_type" (fun x -> V_String (Tls.string_of_content_type (Tls.type_of_record_content x.Tls.content)));
  let hsmsgs_of_record r = match r.Tls.content with
    | Tls.Handshake h -> V_String (Tls.string_of_handshake_msg_type (Tls.type_of_handshake_msg h))
    | _ -> raise Not_found
  in add_tls_field "handshake_msg_type" hsmsgs_of_record;
  let certs_of_record r = match r.Tls.content with
    | Tls.Handshake (Tls.Certificate certs) ->
      let aux cert = V_Certificate cert in
      V_List (List.map aux certs)
    | _ -> raise Not_found
  in add_tls_field "certificates" certs_of_record;
  (* TODO: Other infos (random, compression, ciphers)? *)

  add_asn1_field "class" (fun x -> V_String (Asn1.string_of_class x.Asn1.a_class));
  add_asn1_field "tag" (fun x -> V_Int (x.Asn1.a_tag));
  add_asn1_field "tag_str" (fun x -> V_String (Asn1.string_of_tag x.Asn1.a_class x.Asn1.a_tag));
  add_asn1_field "is_constructed" (fun x -> V_Bool (Asn1.isConstructed x));
  let value_of_asn1_content o = match o.Asn1.a_content with
    | Asn1.Null
    | Asn1.EndOfContents -> V_Unit
    | Asn1.Boolean b -> V_Bool b
    | Asn1.Integer i -> V_String (Common.hexdump_int_list i)
    | Asn1.BitString (_, s) -> V_String (Common.hexdump s)
    | Asn1.OId oid -> V_List (List.map (fun x -> V_Int x) (Asn1.oid_expand oid))
    | Asn1.Unknown s
    | Asn1.String (s, true) -> V_String (Common.hexdump s)
    | Asn1.String (s, false) -> V_String s
    | Asn1.Constructed objs -> V_List (List.map (fun x -> V_Asn1 x) objs)
  in
  add_asn1_field "content" value_of_asn1_content;

  (* TODO: let add_dn_field name f = Hashtbl.replace dn_field_access name f *)
