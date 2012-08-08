type pouet = string * string

record_def answer_dump [lwt] = {
  ip : ipv4;
  ips: (ipv6) list (Var uint32);
  port : uint16;
  name : string (Var uint16);
  client_hello_type : uint8;
  msg_type : uint8;
  content : binstring (Var uint32);
  test : string (Fixed 4);
  other : pouet;
  custom : ((pouet) list (Fixed 4)) list (Fixed 4);
  remaining : string;
}

(* let _ = *)
(*   TODO: test something! *)
