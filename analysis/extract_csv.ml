open Common
open Base64
open Types
open ParsingEngine
open BinaryRecord
open AnswerDump
open Tls
open TlsCommon
open TlsRecord
open TlsHandshake
open TlsAlert


(*
CLIENTHELLO_PATH=~/dev/ssl-campaigns/client-hellos CAMPAIGN_PATH=/media/disk/Campaigns ANALYSIS_PATH=/media/disk/Analysis-ng
for campaign in 00{0,1,2,3,4,5,6,7,8,9}; do
  echo "Working on campaign $campaign"
  export ClientHello="$(openssl enc -base64 -in "$CLIENTHELLO_PATH/$campaign.client_hello")"
  for i in $(seq 0 255); do
  echo -n "  $i... "
  ./extract_csv.native 2> /dev/null < "$CAMPAIGN_PATH/$campaign"*/"$i.dump" | ./split_data.py "$ANALYSIS_PATH/$campaign/$i-%s.txt"
  echo done
done; done
*)


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
  | Alert of int * int * int
  | ServerHello of int * int * int * int list
  | Certificates of string list
  | DHE_SKE of string * string * string
  | ECDHE_SKE of string
  | Other_SKE of string
  | CertificateRequest
  | ServerHelloDone
  | Other_HS of int
  | ToBeIgnored


let mk_uid answer answer_number =
  let ip_part = hexdump (eval_as_ipv4 (answer --> "ip")) in
  let campaign_part = hexdump_int_n 2 (eval_as_int (answer --> "client_hello_type")) in
  let res = ip_part ^ campaign_part ^ (hexdump_int_n 6 !answer_number) in
  incr answer_number;
  res

let mk_hash s =
  String.sub (hexdump (Crypto.sha1sum s)) 0 16


let get_type cs parsing_ended record =
  if !parsing_ended then ToBeIgnored else begin
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
	      ServerHello (record.version, version, ciphersuite, extensions)
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
	    | 14 -> parsing_ended := true; ServerHelloDone
	    | _ -> Other_HS hs_t
	with _ -> parsing_ended := true; Junk
      end
      | 21 -> begin
	try
	  let (al, at) = AlertModule.pop_object record.content in
	  Alert (record.version, al, at)
	with _ -> parsing_ended := true; Junk
      end
      | _ -> parsing_ended := true; Junk
  end


let rec print_hsmsg uid = function
  | (Certificates certs)::r ->
    let sums = List.map mk_hash certs in
    let certificate_chain_id = mk_hash (String.concat "" sums) in
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



exception WrongTLSAnswer

let rec acceptable_versions min max = match min, max with
  | 0x0002, 0x0002 -> [0x0002]
  | 0x0002, _ -> 0x0002::(acceptable_versions 0x0300 max)
  | _ ->
    if min = max
    then [min]
    else min::(acceptable_versions (min+1) max)

let handle_rfc5746 cs exts =
  let rec aux cs_accu exts_accu = function
    | [] -> List.rev cs_accu, exts_accu
    | x::r ->
      if x = 0x00ff
      then aux cs_accu (65281::exts_accu) r
      else aux (x::cs_accu) exts_accu r
  in aux [] exts cs


let describe_ch s =
  let pstate = pstate_of_string None s in
  try
    let records, error = Tls.TlsLib.shallow_parse_records pstate in
    let parsed_recs = Tls.TlsLib._deep_parse_aux "client_hello" records true in
    match parsed_recs with
      | [{content_type = 0x16; content = c}] ->
	begin
	  match HandshakeModule.pop_object c with
	    | 1, V_Dict ch ->
	      let vmax = eval_as_int (ch --> "version")
	      and ciphersuites = List.map eval_as_int (eval_as_list (ch --> "cipher_suites"))
	      and extensions = match (ch --> "extensions") with
		| V_List l -> List.map (fun x -> eval_as_int (List.hd (eval_as_list x))) l
		| _ -> []
	      in
	      let real_cs, real_exts = handle_rfc5746 ciphersuites extensions in
	      (acceptable_versions 0x0300 vmax, real_cs, real_exts)
	    | _ -> raise WrongTLSAnswer
	end
      | _ -> raise WrongTLSAnswer
  with WrongTLSAnswer ->
    let pstate = pstate_of_string None s in
    match Ssl2.parse pstate with
      | Ssl2.ClientHello (vmax, ciphersuites, _sid, _challenge) ->
	let real_cs, real_exts = handle_rfc5746 ciphersuites [] in
	(acceptable_versions 0x0002 vmax, real_cs, real_exts)
      | _ -> raise WrongTLSAnswer


let mk_hs_type version_ok cs_ok ext_ok =
  match version_ok && cs_ok && ext_ok with
    | true -> "H"
    | false ->
      let res = String.copy "h(vce)" in
      if version_ok then res.[2] <- 'V';
      if cs_ok then res.[3] <- 'C';
      if ext_ok then res.[4] <- 'E';
      res



let _ =
  TlsHandshake.parse_certificates := false;
  tolerance := s_specfatallyviolated;
  minDisplay := s_specfatallyviolated;

  let client_hello = from_base64 None (Sys.getenv "ClientHello") in
  let existing_versions = acceptable_versions 0x0002 0x0303 in
  let compatible_versions, acceptable_ciphersuites, acceptable_extensions = describe_ch client_hello in

  let pstate = pstate_of_channel "(stdin)" stdin in
  try
    let answer_number = ref 0 in
    while not (eos pstate) do
      let answer = BinaryRecord.parse AnswerDump.description pstate in
      let uid = mk_uid answer answer_number in

      let name = eval_as_string (answer --> "name") in
      if String.length name > 0
      then Printf.printf "Names:%s:%s\n" uid name;

      let content = eval_as_string (answer --> "content") in
      let tls_pstate = pstate_of_string (Some name) content in
      let records, error = Tls.TlsLib.shallow_parse_records tls_pstate in
      let parsed_recs = Tls.TlsLib._deep_parse_aux name records true in

      let cs = ref None and parsing_ended = ref false in
      let content_types = List.filter (fun x -> x != ToBeIgnored && x != ServerHelloDone) (List.map (get_type cs parsing_ended) parsed_recs) in

      begin
	match content_types with
	  | [Alert (version, al, at)] ->
	    if List.mem version existing_versions
	    then Printf.printf "AnswerTypes:%s:A:%4.4x:%d:%d\n" uid version al at
	    else Printf.printf "AnswerTypes:%s:J\n" uid
	  | (ServerHello (_, version, cs, exts))::r ->
	    let version_ok = List.mem version compatible_versions
	    and cs_ok = List.mem cs acceptable_ciphersuites
	    and ext_ok = List.fold_left ( && ) true (List.map (fun e -> List.mem e acceptable_extensions) exts) in
	    let t = mk_hs_type version_ok cs_ok ext_ok in
	    let ext_str = String.concat "," (List.map string_of_int exts) in
	    Printf.printf "AnswerTypes:%s:%s:%4.4x:%4.4x:%s\n" uid t version cs ext_str;
	    print_hsmsg uid r
	  | _ ->
	    begin
	      let ssl2_pstate = pstate_of_string (Some name) content in
	      let res =
		try Some (Ssl2.parse ssl2_pstate)
		with _ -> None
	      in
	      match res with
		| Some (Ssl2.Error err) -> Printf.printf "AnswerTypes:%s:A:0002:%d:%d\n" uid (err lsr 8) (err land 0xff)
		| Some (Ssl2.ServerHello (_session_id_hit, _cert_type, v, cert, cs::_, _connection_id)) ->
		  let version_ok = List.mem 0x0002 compatible_versions
		  and cs_ok = List.mem cs acceptable_ciphersuites in
		  let t = mk_hs_type version_ok cs_ok true in
		  Printf.printf "AnswerTypes:%s:%s:%4.4x:%4.4x:\n" uid t v cs;
		  print_hsmsg uid [Certificates [cert]]
		| _ -> Printf.printf "AnswerTypes:%s:%c\n" uid (if content = "" then 'E' else 'J')
	    end
      end
    done
  with
    | OutOfBounds s ->
      output_string stderr ("Out of bounds (" ^ s ^ ")\n")
    | ParsingError (err, sev, pstate) ->
      output_string stderr ((string_of_parsing_error "Parsing error" err sev pstate) ^ "\n");;
