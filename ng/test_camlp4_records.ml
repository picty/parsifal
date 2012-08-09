record_def answer_dump [lwt] = {
  ip : ipv4;
  port : uint16;
  name : string(uint16);
  client_hello_type : uint8;
  msg_type : uint8;
  content : binstring(uint32);
}

(*
  test : string(4);
  optional other : pouet;
  optional custom : list(4) of (list(4) of pouet);
  remaining : string;
*)

(* let _ = *)
(*   TODO: test something! *)
