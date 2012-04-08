open Common
open Types
open ParsingEngine
open BinaryRecord
open AnswerDump
open Tls
open TlsCommon
open TlsRecord
open TlsHandshake
open TlsAlert


let dhe_suites =
  [0x0011; 0x0012; 0x0013; 0x0014; 0x0015; 0x0016; 0x002d; 0x0032;
   0x0033; 0x0038; 0x0039; 0x0040; 0x0044; 0x0045; 0x0067; 0x006a;
   0x006b; 0x0087; 0x0088; 0x008e; 0x008f; 0x0090; 0x0091; 0x0099;
   0x009a; 0x009e; 0x009f; 0x00a2; 0x00a3; 0x00aa; 0x00ab; 0x00b2;
   0x00b3; 0x00b4; 0x00b5; 0x00bd; 0x00be; 0x00c3; 0x00c4; 0xc042;
   0xc043; 0xc044; 0xc045; 0xc052; 0xc053; 0xc056; 0xc057; 0xc066;
   0xc067; 0xc06c; 0xc06d; 0xc07c; 0xc07d; 0xc080; 0xc081; 0xc090;
   0xc091; 0xc096; 0xc097]

let ecdhe_suites =
  [0xc006; 0xc007; 0xc008; 0xc009; 0xc00a; 0xc010; 0xc011; 0xc012;
   0xc013; 0xc014; 0xc023; 0xc024; 0xc027; 0xc028; 0xc02b; 0xc02c;
   0xc02f; 0xc030; 0xc033; 0xc034; 0xc035; 0xc036; 0xc037; 0xc038;
   0xc039; 0xc03a; 0xc03b; 0xc048; 0xc049; 0xc04c; 0xc04d; 0xc05c;
   0xc05d; 0xc060; 0xc061; 0xc070; 0xc071; 0xc072; 0xc073; 0xc076;
   0xc077; 0xc086; 0xc087; 0xc08a; 0xc08b; 0xc09a; 0xc09b]


type msg =
  | Junk
  | Alert of int * int
  | ServerHello of int * int * int list
  | Certificates of string list
  | DHE_SKE of string * string * string
  | ECDHE_SKE of string
  | Other_SKE of string
  | CertificateRequest
  | ServerHelloDone
  | Other_HS of int





let get_name answer =
  let name = eval_as_string (answer --> "name") in
  if String.length name = 0
  then Common.string_of_ip4 (eval_as_ipv4 (answer --> "ip"))
  else name

let get_ip answer = Common.string_of_ip4 (eval_as_ipv4 (answer --> "ip"))

let string_of_type = function
  | Junk -> "Junk"
  | Alert (al, at) ->
    "A(" ^ (string_of_int al) ^ "," ^ (string_of_int at) ^ ")"
  | ServerHello (v, cs, exts) ->
    "SH(" ^ (hexdump_int_n 4 v) ^ "," ^ (hexdump_int_n 4 cs) ^ ",{" ^
      (String.concat ";" (List.map string_of_int exts)) ^  "})"
  | Certificates certs -> "Certs(" ^ (string_of_int (List.length certs)) ^ ")"
  | CertificateRequest -> "CertReq"
  | DHE_SKE (_, _, _) -> "SKE(DHE)"
  | ECDHE_SKE _ -> "SKE(ECDHE)"
  | Other_SKE _ -> "SKE"
  | ServerHelloDone -> "SHD"
  | Other_HS hs_type -> "HS" ^ (string_of_int hs_type)


let get_type cs shdone record =
  if !shdone then Junk else begin
    let msg_type = record.content_type in
    match msg_type with
      | 22 -> begin
	try
	  let (hs_t, hs_msg) = HandshakeModule.pop_object record.content in
	  match hs_t with
	    | 2 ->
	      let sh = eval_as_dict hs_msg in
	      let version = eval_as_int (sh --> "version")
	      and ciphersuite = eval_as_int (sh --> "cipher_suite")
	      and extensions = match (sh --> "extensions") with
		| V_List l -> List.map (fun x -> eval_as_int (List.hd (eval_as_list x))) l
		| _ -> []
	      in
	      cs := Some ciphersuite;
	      ServerHello (version, ciphersuite, extensions)
	    | 11 -> Certificates (List.map eval_as_string (eval_as_list hs_msg))
	    | 12 -> begin
	      match !cs with
		| None -> Other_SKE ""
		| Some cs ->
		  if List.mem cs dhe_suites
		  then DHE_SKE ("","","")
		  else if List.mem cs ecdhe_suites
		  then ECDHE_SKE ""
		  else Other_SKE ""
	    end
	    | 13 -> CertificateRequest
	    | 14 -> shdone := true; ServerHelloDone
	    | _ -> Other_HS hs_t
	with _ -> shdone := true; Junk
      end
      | 21 -> begin
	try
	  let (al, at) = AlertModule.pop_object record.content in
	  Alert (al, at)
	with _ -> shdone := true; Junk
      end
      | _ -> shdone := true; Junk
  end


let rec print_hsmsg uid = function
  | (Certificates certs)::r ->
    let sums = List.map (fun s -> hexdump (Crypto.sha1sum s)) certs in
    let certificate_chain_id = hexdump (Crypto.sha1sum (String.concat "" sums)) in
    Printf.printf "CertificateChains:%s:%s\n" uid certificate_chain_id;
    let rec aux i = function
      | c::rc, s::rs ->
	Printf.printf "Certificates:%s:%d:%s\n" certificate_chain_id i s;
	Printf.printf "CertificateContents:%s:%s\n" s (Base64.to_raw_base64 c);
	aux (i+1) (rc, rs)
      | _ -> ()
    in aux 0 (certs, sums);
    print_hsmsg uid r
  (* TODO: Handle other messages *)
  | _ -> ()


let _ =
  let pstate = pstate_of_channel "(stdin)" stdin in

  TlsHandshake.parse_certificates := false;
  tolerance := s_specfatallyviolated;
  minDisplay := s_specfatallyviolated;
  
  try
    while not (eos pstate) do
      let answer = BinaryRecord.parse AnswerDump.description pstate in

      let name = get_name answer in
      let campaign = eval_as_int (answer --> "client_hello_type") in
      let ip = get_ip answer in
      let unique_id = hexdump (Crypto.sha1sum ((string_of_int campaign) ^ ":" ^ name ^ ":" ^ ip)) in

      Printf.printf "UniqueIds:%3.3d:%s:%s:%s\n" campaign name ip unique_id;

      let tls_pstate = pstate_of_string (Some name) (eval_as_string (answer --> "content")) in
      let records, error = Tls.TlsLib.shallow_parse_records tls_pstate in
      let parsed_recs = Tls.TlsLib._deep_parse_aux name records true in

      let cs = ref None and shdone = ref false in
      let content_types = List.filter (fun x -> x != Junk && x != ServerHelloDone) (List.map (get_type cs shdone) parsed_recs) in

      begin
	match content_types with
	  | (Alert (al, at))::_ -> 
	    Printf.printf "AnswerTypes:%s:Alert\n" unique_id;
	    Printf.printf "Alerts:%s:%d:%d\n" unique_id al at;
	  | (ServerHello (v, cs, exts))::r ->
	    Printf.printf "AnswerTypes:%s:Handshake\n" unique_id;
	    Printf.printf "ServerHellos:%s:%4.4x:%4.4x\n" unique_id v cs;
	    List.iter (fun e -> Printf.printf "ServerHelloExtensions:%s:%d\n" unique_id e) exts;
	    print_hsmsg unique_id r
	  | _ ->
	    Printf.printf "AnswerTypes:%s:Junk\n" unique_id;
      end
    done
  with
    | OutOfBounds s ->
      output_string stderr ("Out of bounds (" ^ s ^ ")\n")
    | ParsingError (err, sev, pstate) ->
      output_string stderr ((string_of_parsing_error "Parsing error" err sev pstate) ^ "\n");;
