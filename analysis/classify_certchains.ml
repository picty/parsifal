open Common


(* Types *)

type keytype_t = RSA of int | DSA | UnknownKeyType
type trust_t = NotTrusted | Trusted of string list

type cert_parsed = {
  cert_id : string;
  version : int;
  serial : string;
  notbefore : string;
  notafter : string;
  issuer_id : string;
  issuer : string;
  subject_id : string;
  subject : string;
  keytype : keytype_t;
  ca : bool;
  ski : string;
  aki_serial : string;
  aki_ki : string;
  cert_policies : string list;
  trust : trust_t
}

type chain_details = {
  chain_built : string list;
  n_dups : int;
  n_outside : int;
  n_unused : int;
  n_total : int;
  rfc_compliant : bool;
  trusted : trust_t;
  (* valdity, etc. *)
}

type chain_parsed = UnbuiltChain of cert_parsed list | BuiltChain of chain_details



(* Globals *)

let cert_by_id = Hashtbl.create 1000
let cert_by_subject = Hashtbl.create 1000
let chain_by_id = Hashtbl.create 1000
let dn_by_id = Hashtbl.create 1000



(* Load functions *)

let load_dns filename =
  let dns = open_in filename in
  try
    while true do
      match Common.string_split ':' (input_line dns) with
	| [id_s; dn_s] ->
	  let dn_id = hexparse id_s in
	  Hashtbl.replace dn_by_id dn_id dn_s
	| _ -> failwith "Wrong dn line"
    done
  with End_of_file -> close_in dns

let add_cert cert_line trust_info =
  match Common.string_split ':' cert_line with
    | [id_s; ver_s; ser_s; nb_s; na_s; _; iss_s; sub_s;
       key_s; _; ksz_s; ca_s; ski_s; akiser_s; aki_s; cps_s] ->
      let id = hexparse id_s
      and version = match ver_s with "" -> 1 | _ -> int_of_string ver_s
      and keytype = match key_s, ksz_s with
	| "RSA", sz -> RSA (int_of_string sz)
	| "DSA", _  -> DSA
	| _         -> UnknownKeyType
      and ca = match ca_s with "Yes" | "MostlyYes" -> true | _ -> false
      and i_id = hexparse iss_s
      and s_id = hexparse sub_s in
      let content = {
	cert_id = id;
	version = version;
	serial = hexparse ser_s;
	notbefore = nb_s;
	notafter = na_s;
	issuer_id = i_id;
	issuer = Hashtbl.find dn_by_id i_id;
	subject_id = s_id;
	subject = Hashtbl.find dn_by_id s_id;
	keytype = keytype;
	ca = ca;
	ski = hexparse ski_s;
	aki_serial = hexparse akiser_s;
	aki_ki = hexparse aki_s;
	cert_policies = string_split ',' cps_s;
	trust = trust_info
      } in
      if not (Hashtbl.mem cert_by_id id)
      then begin
	Hashtbl.replace cert_by_id id content;
	Hashtbl.add cert_by_subject s_id content
      end
    | _ -> failwith "Wrong certificate line"

let load_certs filename trusted =
  let certs = open_in filename in
  let trust_info = if trusted then Trusted [] else NotTrusted in
  try
    while true do
      add_cert (input_line certs) trust_info
    done
  with End_of_file -> close_in certs

let load_chains filename =
  let chains = open_in filename in
  let current = ref [] in
  let current_id = ref "" in
  try
    while true do
      match Common.string_split ':' (input_line chains) with
	| [chain_s; _; cert_s] ->
	  let chain_id = hexparse chain_s
	  and cert_id = Hashtbl.find cert_by_id (hexparse cert_s) in
	  if !current_id != chain_id
	  then begin
	    if !current != []
	    then Hashtbl.replace chain_by_id !current_id (UnbuiltChain (List.rev !current));
	    current := [cert_id];
	    current_id := chain_id
	  end else current := cert_id::(!current)
	| _ -> failwith "Wrong chain line"
    done
  with End_of_file ->
    if !current != []
    then Hashtbl.replace chain_by_id !current_id (UnbuiltChain (List.rev !current));
    close_in chains



(* Chain construction and check *)

let check_link subject issuer end_entity =
  (subject.issuer_id == issuer.subject_id) &&
    (subject.aki_serial == "" || subject.aki_serial == issuer.serial) &&
    (subject.aki_ki == "" || subject.aki_ki == issuer.ski) &&
    ((end_entity && subject.cert_id == issuer.cert_id) || subject.ca)

let clean_chain c =
  let certs_seen = Hashtbl.create 10 in
  let rec filter_dups n_dups accu = function
    | [] -> n_dups, List.rev accu
    | cert::r ->
      if Hashtbl.mem certs_seen cert.cert_id
      then filter_dups (n_dups + 1) accu r
      else begin
	Hashtbl.add certs_seen cert.cert_id ();
	filter_dups n_dups (cert::accu) r
      end
  in filter_dups 0 [] c

let is_trusted c = (List.hd (List.rev c)).trust != NotTrusted

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
      if c == x
      then aux accu r
      else aux (x::accu) r
  in aux [] l

let rec step used n_outside chain_so_far next remaining_certs =
  if check_link next next (chain_so_far == [])
  then Some ((List.rev (next::chain_so_far)), n_outside)
  else begin
    let expected_iss = next.issuer_id in
    let inchain_candidates = List.filter
      (fun c -> (c.subject_id == expected_iss) && (not (List.mem c used)))
      remaining_certs
    and outside_candidates = List.filter
      (fun c -> (not (List.mem c remaining_certs)) && (not (List.mem c used)))
      (Hashtbl.find_all cert_by_subject expected_iss)
    in
    let rec next_step new_n_outside new_chain current = function
      | [] -> current
      | cert::r ->
	let x = step (cert::used) new_n_outside new_chain cert
	  (filter_out cert remaining_certs)
	in
	let new_current = match current, x with
	 | None, _ -> x
	 | _, None -> current
	 | Some a, Some b -> Some (return_better_chain a b)
	in
	next_step new_n_outside new_chain new_current r
    in
    let after_inchain = next_step n_outside (next::chain_so_far) None inchain_candidates in
    next_step (n_outside + 1) (next::chain_so_far) after_inchain outside_candidates
  end


let rec is_rfc_compliant chain_sent chain_built =
  match chain_sent, chain_built with
    | [], [] -> true
    | [], [c] -> true
    | a::r, b::s -> a = b && is_rfc_compliant r s
    | _, _ -> false


let analyse_chain chain =
  let n_dups, clean_chain = clean_chain chain in
  match chain with
    | [] -> { chain_built = [];
	      n_dups = 0;
	      n_outside = 0;
	      n_unused = 0;
	      n_total = 0;
	      rfc_compliant = false;
	      trusted = NotTrusted }
    | first::r ->
      match step [first] 0 [] first r with
	| Some (ch, n_out) ->
	  { chain_built = ch;
	    n_dups = n_dups;
	    n_outside = n_out;
	    n_unused = (List.length clean_chain) + n_outside - (List.length ch);
	    n_total = List.length clean_chain;
	    rfc_compliant = is_rfc_compliant chain ch;
	    trusted = (List.hd (List.rev ch)).trust != NotTrusted
	  }
	| None ->
	  { chain_built = [];
	    n_dups = 0;
	    n_outside = 0;
	    n_unused = 0;
	    n_total = 0;
	    rfc_compliant = false;
	    trusted = NotTrusted }
(*     # Add info on the end entity cert (EV ext? DN type?) *)
(*     # Enrich : is_valid_in_FF, is_EV *)
(*     # Compute validities, chain quality (Algos, RSA keysizes, validity) *)


let _ =
  load_dns "108-DistinguishedNames.txt";
  load_certs "trusted-CertificateParsed.txt" true;
  load_certs "108-CertificateParsed.txt" false;
  load_chains "108-Certificates.txt";

(* Add a list of EV certificate policies extensions *)




(* trusted_ok = 0 *)
(* complete_ok = 0 *)
(* complete_transvalid_ok = 0 *)
(* malformed_trusted_ok = 0 *)
(* malformed_complete_ok = 0 *)
(* malformed_complete_transvalid_ok = 0 *)
(* nok = 0 *)
(* nok_ids = [] *)
(* for i in chain_by_id.keys(): *)
(*   res = analyse_chain (i) *)
(*   if res == None: *)
(*     nok += 1 *)
(*     nok_ids += [i] *)
(*     continue *)

(*   chain, n_duplicates, n_outside, n_unused, n_total, rfc_compliant, trusted = res *)
(*   if rfc_compliant and trusted: *)
(*     trusted_ok += 1 *)
(*   elif rfc_compliant: *)
(*     complete_ok += 1 *)
(*   elif n_unused + n_duplicates == 0: *)
(*     complete_transvalid_ok += 1 *)
(*   elif trusted and n_outside == 0: *)
(*     malformed_trusted_ok += 1 *)
(*   elif n_outside == 0: *)
(*     malformed_complete_ok += 1 *)
(*   else: *)
(*     malformed_complete_transvalid_ok += 1 *)

(* # Try to establish all the complete chains and classify them with the following order *)
(* #   T-Trusted -> the root is trusted *)
(* #   C-RFC Compliant -> chain_sent == chain or chain_sent == chain[:-1] *)
(* #   V-Transvalid -> certs not sent were necessary *)
(* #   TCv > TCV > Tcv > TcV > tCv > tCV > tcv > tcV *)

(* #  print "%16.16x %s" % (i, res) *)


(* def show (chain_to_test): *)
(*   for i in chain_by_id[chain_to_test]: *)
(*     print cert_by_id[i], dn_by_id[cert_by_id[i][4]], dn_by_id[cert_by_id[i][5]] *)


(* #chain_by_id[0x69421ef2ce7d842a] *)
(* #[13526490820496635828L, 15892318145452193511L, 9980059178342203074L, 214752086678787176] *)

(* #0x69421ef2ce7d842a -> pas dans l'ordre *)
