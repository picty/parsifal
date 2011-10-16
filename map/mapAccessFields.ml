open MapLang

let add_cert_field name f =
  Hashtbl.replace certificate_field_access name f

let add_answer_field name f =
  Hashtbl.replace answer_field_access name f

let _ =
  add_answer_field "ip" (fun x -> V_String (Common.string_of_ip x.AnswerDump.ip));
  add_answer_field "port" (fun x -> V_Int x.AnswerDump.port);
  add_answer_field "name" (fun x -> V_String x.AnswerDump.name);
  add_answer_field "client_hello_type" (fun x -> V_Int x.AnswerDump.client_hello_type);
  add_answer_field "msg_type" (fun x -> V_Int x.AnswerDump.msg_type);
  add_answer_field "content" (fun x -> V_String x.AnswerDump.content);
