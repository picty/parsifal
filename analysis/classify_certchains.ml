let string_split c s =
  let rec aux offset =
    try
      let next_index = String.index_from s offset c in
      (String.sub s offset (next_index - offset))::(aux (next_index + 1))
    with Not_found ->
      let len = String.length s in
      if offset < len then [String.sub s offset (len - offset)] else [""]
  in aux 0

let mk_id s = Common.hexparse s


(* Types *)

type keytype_t = RSA of int | PartialRSA of int | DSA | UnknownKeyType

type cert_parsed = {
  cert_id : string;
  version : int;
  serial : string;
  not_before : string;
  not_after : string;
  issuer_id : string;
  subject_id : string;
  keytype : keytype_t;
  ca : bool;
  ski : string;
  aki_serial : string;
  aki_ki : string;
  cert_policies : string list;
  cert_trust : bool
}

type unordered_chain_details = {
  n_dups : int;
  n_outside : int;
  n_unused : int;
  n_sent : int;
}

type chain_type =
  | CT_Perfect of int * bool
  | CT_Trusted of int * bool * unordered_chain_details
  | CT_CompleteRFC of int * bool
  | CT_Complete of int * bool * unordered_chain_details
  | CT_Incomplete

(* Add DN *)
type chain_details = {
  chain_type  : chain_type;
  validity    : string * string;
  key_quality : keytype_t;
  _hostname   : string;
  ev_cps      : bool;
}



(* Globals *)

let cert_by_id = Hashtbl.create 10000000
let cert_by_subject = Hashtbl.create 10000000
let dn_by_id = Hashtbl.create 10000000
let ev_by_oid = Hashtbl.create 100

let find h hname key =
  try Hashtbl.find h key
  with Not_found -> failwith ("Unable to find " ^ (Common.hexdump key) ^ " in " ^ hname)

let find_dn_by_id = find dn_by_id "dn_by_id"


(* Load functions *)

let load_dns filename =
  Printf.fprintf stderr "Loading %s... " filename;
  flush stderr;
  let dns = open_in filename in
  try
    while true do
      let line = input_line dns in
      match string_split ':' line with
	| [id_s; dn_s] ->
	  let dn_id = mk_id id_s in
	  Hashtbl.replace dn_by_id dn_id dn_s
	| [id_s] ->
	  let dn_id = mk_id id_s in
	  Hashtbl.replace dn_by_id dn_id ""
	| _ -> failwith ("Wrong dn line \"" ^ line ^ "\"")
    done
  with End_of_file ->
    close_in dns;
    Printf.fprintf stderr "done\n";
    flush stderr

let load_evs filename =
  Printf.fprintf stderr "Loading %s..." filename;
  flush stderr;
  let evs = open_in filename in
  try
    while true do
      let line = input_line evs in
      match string_split ':' line with
	| [dn_s; oid] ->
	  let dn_id = mk_id dn_s in
	  Hashtbl.replace ev_by_oid oid dn_id
	| [id_s] ->
	  let dn_id = mk_id id_s in
	  Hashtbl.replace dn_by_id dn_id ""
	| _ -> failwith ("Wrong ev line \"" ^ line ^ "\"")
    done
  with End_of_file ->
    close_in evs;
    Printf.fprintf stderr "done\n";
    flush stderr

let add_cert cert_line trust_info =
  match string_split ':' cert_line with
    | [id_s; ver_s; ser_s; nb_s; na_s; _; iss_s; sub_s;
       key_s; _; ksz_s; ca_s; ski_s; akiser_s; aki_s; cps_s] ->
      let id = mk_id id_s
      and version = match ver_s with "" -> 1 | _ -> int_of_string ver_s
      and keytype = match key_s, ksz_s with
	| "RSA", sz -> RSA (int_of_string sz)
	| "DSA", _  -> DSA
	| _         -> UnknownKeyType
      and ca = match ca_s with "Yes" | "MostlyYes" -> true | _ -> false
      and i_id = mk_id iss_s
      and s_id = mk_id sub_s in
      let content = {
	cert_id = id;
	version = version;
	serial = Common.hexparse ser_s;
	not_before = nb_s;
	not_after = na_s;
	issuer_id = i_id;
	subject_id = s_id;
	keytype = keytype;
	ca = ca;
	ski = Common.hexparse ski_s;
	aki_serial = Common.hexparse akiser_s;
	aki_ki = Common.hexparse aki_s;
	cert_policies = string_split ',' cps_s;
	cert_trust = trust_info
      } in
      if not (Hashtbl.mem cert_by_id id)
      then begin
	Hashtbl.replace cert_by_id id content;
	Hashtbl.add cert_by_subject s_id content
      end
    | l -> failwith ("Wrong certificate line \"" ^ cert_line ^ "\", " ^ (string_of_int (List.length l)))

let load_certs filename trust_info =
  Printf.fprintf stderr "Loading %s... " filename;
  flush stderr;
  let certs = open_in filename in
  try
    while true do
      add_cert (input_line certs) trust_info;
    done
  with End_of_file ->
    close_in certs;
    Printf.fprintf stderr "done\n";
    flush stderr


(* Chain finalization *)

let wrong_chain cert = {
  chain_type = CT_Incomplete;
  validity = cert.not_before, cert.not_after;
  key_quality = cert.keytype;
  _hostname = "";
  ev_cps = false
}

let empty_chain () = {
  chain_type = CT_Incomplete;
  validity = "", "";
  key_quality = UnknownKeyType;
  _hostname = "";
  ev_cps = false
}

let rec is_rfc_compliant chain_sent chain_built =
  match chain_sent, chain_built with
    | [], [] -> true, true
    | [], [c] -> true, false
    | a::r, b::s when a = b -> is_rfc_compliant r s
    | _, _ -> false, false

let is_root_included chain_sent chain_built =
  let root_cert = List.hd (List.rev chain_built) in
  List.mem root_cert chain_sent

let date_of_str s =
  match List.map int_of_string (string_split '-' s) with
    | [y; m; d] -> (y, m, d)
    | _ -> failwith "Wrong date"

let rec mk_validity = function
  | []   -> "", ""
  | [c]  -> (c.not_before, c.not_after)
  | c::r ->
    let nb, na = mk_validity r in
    (max c.not_before nb, min c.not_after na)

let rec mk_key_quality = function
  | []   -> UnknownKeyType
  | [c]  -> c.keytype
  | c::r ->
    match c.keytype, (mk_key_quality r) with
      | RSA n1, RSA n2 -> RSA (min n1 n2)
      | RSA n1, PartialRSA n2
      | PartialRSA n1, RSA n2 -> PartialRSA (min n1 n2)
      | RSA n, _ | _, RSA n | _, PartialRSA n -> PartialRSA n
      | DSA, DSA -> DSA
      | _, _ -> UnknownKeyType

let find_ev_dn oid =
  try Hashtbl.find ev_by_oid oid
  with Not_found -> ""

let build_chain chain_sent chain_built n_dups n_out n_unused =
  let rfc_compliant, root_included = is_rfc_compliant chain_sent chain_built
  and len_sent = List.length chain_sent
  and len = List.length chain_built
  and root = List.hd (List.rev chain_built) in
  let t = match root.cert_trust, rfc_compliant with
    | true, true   -> CT_Perfect (len, root_included)
    | true, false  -> CT_Trusted (len, is_root_included chain_sent chain_built,
				       { n_dups = n_dups; n_outside = n_out; n_unused = n_unused; n_sent = len_sent })
    | false, true  -> CT_CompleteRFC (len, root_included)
    | false, false -> CT_Complete (len, is_root_included chain_sent chain_built,
				        { n_dups = n_dups; n_outside = n_out; n_unused = n_unused; n_sent = len_sent })
  and expected_ev_dns = List.map find_ev_dn ((List.hd chain_built).cert_policies)
  in
  {
    chain_type = t;
    validity = mk_validity chain_built;
    key_quality = mk_key_quality chain_built;
    _hostname = "";
    ev_cps = List.mem root.subject_id expected_ev_dns
  }

let string_of_chain_type t =
  let c, l = match t with
    | CT_Perfect (n, true)      -> "P", [n; n; 0; 0; 0]
    | CT_Perfect (n, false)     -> "P", [n-1; n; 0; 0; 0]

    | CT_Trusted (n, root_inside, x) ->
      let trusted_or_transvalid = match root_inside, x.n_outside with
	| true, 0 | false, 1 -> "T"
	| _ -> "t"
      in trusted_or_transvalid, [x.n_sent; n; x.n_dups; x.n_outside; x.n_unused]

    | CT_CompleteRFC (n, true)  -> "R", [n; n; 0; 0; 0]
    | CT_CompleteRFC (n, false) -> "R", [n-1; n; 0; 0; 0]

    | CT_Complete (n, root_inside, x) ->
      let complete_or_transvalid = match root_inside, x.n_outside with
	| true, 0 | false, 1 -> "C"
	| _ -> "c"
      in complete_or_transvalid, [x.n_sent; n; x.n_dups; x.n_outside; x.n_unused]

    | CT_Incomplete             -> "I", [0; 0; 0; 0; 0]
  in
  String.concat ":" (c::(List.map string_of_int l))

let string_of_keytype = function
  | RSA n -> "RSA:" ^ (string_of_int n)
  | PartialRSA n -> "rsa:" ^ (string_of_int n)
  | DSA -> "DSA:0"
  | UnknownKeyType -> "Unknown:0"

let string_of_chain_details d =
  String.concat ":" [
    string_of_chain_type d.chain_type;
    fst d.validity; snd d.validity;
    string_of_keytype d.key_quality;
    d._hostname;
    if d.ev_cps then "1" else "0"
  ]



(* Chain construction and check *)

let check_link subject issuer =
  (subject.issuer_id = issuer.subject_id) &&
    (subject.aki_serial = "" || subject.aki_serial = issuer.serial) &&
    (subject.aki_ki = "" || subject.aki_ki = issuer.ski) &&
    issuer.ca

let clean_chain c =
  let rec filter_dups n_dups ids_seen accu = function
    | [] -> n_dups, List.rev accu
    | cert::r ->
      if List.mem cert.cert_id ids_seen
      then filter_dups (n_dups + 1) ids_seen accu r
      else filter_dups n_dups (cert.cert_id::ids_seen) (cert::accu) r
  in filter_dups 0 [] [] c

let is_trusted c = (List.hd (List.rev c)).cert_trust

let return_better_chain a b =
  let (csf1, out1) = a
  and (csf2, out2) = b in
  match is_trusted csf1, is_trusted csf2 with
    | true, false -> a
    | false, true -> b
    | _ ->
      if out1 > out2
      then b
      else if out2 > out1
      then a
      else begin
	if List.length csf2 > List.length csf1
	then a
	else b
      end

let filter_out c l =
  let rec aux accu = function
    | [] -> List.rev accu
    | x::r ->
      if c = x
      then aux accu r
      else aux (x::accu) r
  in aux [] l


let empty_dn = Common.hexparse "da39a3ee5e6b4b0d"

let rec step used n_outside chain_so_far next remaining_certs =
  if check_link next next
  then Some ((List.rev (next::chain_so_far)), n_outside)
  else begin
    let expected_iss = next.issuer_id in
    if expected_iss = empty_dn then None else begin

      let filter_inchain c =
	(c.subject_id = expected_iss) &&
	  (not (List.mem c.cert_id used)) &&
	  (check_link next c)
      and filter_outside c =
	(not (List.mem c remaining_certs)) &&
	  (not (List.mem c.cert_id used)) &&
	  (check_link next c)
      in

      let inchain_candidates = List.filter filter_inchain remaining_certs in
      match next_step used n_outside (next::chain_so_far) None remaining_certs inchain_candidates with
	| (Some (_, nout)) as res when nout = n_outside -> res
	| tmp_res ->
	  let cool_subjects = Hashtbl.find_all cert_by_subject expected_iss in
	  let outside_candidates = List.filter filter_outside cool_subjects in
	  next_step used (n_outside + 1) (next::chain_so_far) tmp_res remaining_certs outside_candidates
    end
  end

and next_step used new_n_outside new_chain current_res remaining_certs = function
  | [] -> current_res
  | cert::r ->
    let x = step (cert.cert_id::used) new_n_outside new_chain cert
      (filter_out cert remaining_certs)
    in
    let new_res = match current_res, x with
      | None, _ -> x
      | _, None -> current_res
      | Some a, Some b -> Some (return_better_chain a b)
    in
    next_step used new_n_outside new_chain new_res remaining_certs r



let foreach_chain f filename =
  let chains = open_in filename in
  let current = ref [] in
  let current_id = ref "" in
  try
    while true do
      match Common.string_split ':' (input_line chains) with
	| [chain_s; _; cert_s] ->
	  let chain_id = mk_id chain_s
	  and cert_id = mk_id cert_s in
	  if !current_id <> chain_id
	  then begin
	    if !current <> []
	    then f !current_id (List.rev !current);
	    current := [cert_id];
	    current_id := chain_id
	  end else current := cert_id::(!current)
	| _ -> failwith "Wrong chain line"
    done
  with End_of_file ->
    if !current <> []
    then f !current_id (List.rev !current);
    close_in chains

let rec certs_of_ids = function
  | [] -> []
  | id::r ->
    try (Hashtbl.find cert_by_id id)::(certs_of_ids r)
    with Not_found -> certs_of_ids r

let analyse_chain chain_ids =
  let chain_sent = certs_of_ids chain_ids in
  let n_dups, clean_chain = clean_chain chain_sent in
  match clean_chain with
    | [] -> empty_chain ()
    | first::r ->
      match step [first.cert_id] 0 [] first r with
	| Some (chain_built, n_out) ->
	  let n_unused = (List.length clean_chain) + n_out - (List.length chain_built) in
	  build_chain chain_sent chain_built n_dups n_out n_unused
	| None -> wrong_chain first


let analyse_and_print i chain =
  let details = analyse_chain chain in
  Printf.printf "%s:%s\n" (Common.hexdump i) (string_of_chain_details details)

let _ =
(*  load_dns "108-DistinguishedNames.txt"; *)
  load_dns "trusted-DistinguishedNames.txt";
  load_certs "trusted-CertificateParsed.txt" true;
  load_certs "CertificateParsed.txt" false;
  load_evs "ExtendedValidation.txt";

  Printf.fprintf stderr "%d dns loaded\n" (Hashtbl.length dn_by_id);
  Printf.fprintf stderr "%d certificates loaded\n" (Hashtbl.length cert_by_id);
  flush stderr;

  foreach_chain analyse_and_print "Certificates.txt"
