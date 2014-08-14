open X509Basics
open X509Extensions
open X509
open Pkcs1


(*************************************)
(* smart_certificate                 *)
(* Wrapper around X.509 certificates *)
(*************************************)

type smart_certificate = {
  name : string;
  trusted_cert : bool;
  mutable raw_value : string option;
  mutable cert_hash : string option;
  mutable parsed_cert : certificate option;
  mutable pos_in_hs_msg : int option;
  mutable subject_hash : string option;
  mutable issuer_hash : string option;
  issued_certs : (string, bool) Hashtbl.t;
}


let sc_of_raw_value name trusted_cert r = {
  name; trusted_cert;
  raw_value = Some r; cert_hash = None;
  parsed_cert = None; pos_in_hs_msg = None;
  subject_hash = None; issuer_hash = None;
  issued_certs = Hashtbl.create 10;
}

let sc_of_raw_value_and_cert name trusted_cert r c = {
  name; trusted_cert;
  raw_value = Some r; cert_hash = None;
  parsed_cert = Some c; pos_in_hs_msg = None;
  subject_hash = None; issuer_hash = None;
  issued_certs = Hashtbl.create 10;
}

let sc_of_cert name trusted_cert c = {
  name; trusted_cert;
  raw_value = None; cert_hash = None;
  parsed_cert = Some c; pos_in_hs_msg = None;
  subject_hash = None; issuer_hash = None;
  issued_certs = Hashtbl.create 10;
}


let raw_value_of_sc sc = match sc.raw_value, sc.parsed_cert with
  | Some r, _ -> r
  | None, Some c ->
    let r = Parsifal.exact_dump dump_certificate c in
    sc.raw_value <- Some r;
    r
  | None, None -> failwith "raw_value_of_sc"

let hash_of_sc sc = match sc.cert_hash with
  | Some h -> h
  | None ->
    let r = raw_value_of_sc sc in
    let h = CryptoUtil.sha1sum r in
    sc.cert_hash <- Some h;
    h

let cert_of_sc sc = match sc.parsed_cert with
  | Some c -> c
  | None ->
    let r = raw_value_of_sc sc in
    let c = parse_certificate (Parsifal.input_of_string sc.name r) in
    sc.parsed_cert <- Some c;
    c

let issuer_hash_of_sc sc = match sc.issuer_hash with
  | Some h -> h
  | None ->
    let parsed_c = cert_of_sc sc in
    let h = match parsed_c.tbsCertificate.issuer_raw with
      | Some s -> CryptoUtil.sha1sum s
      | None -> failwith "issuer_hash_of_sc" (* TODO: dump the dn and update cert? *)
    in
    sc.issuer_hash <- Some h;
    h

let subject_hash_of_sc sc = match sc.subject_hash with
  | Some h -> h
  | None ->
    let parsed_c = cert_of_sc sc in
    let h = match parsed_c.tbsCertificate.subject_raw with
      | Some s -> CryptoUtil.sha1sum s
      | None -> failwith "subject_hash_of_sc" (* TODO: dump the dn and update cert? *)
    in
    sc.subject_hash <- Some h;
    h

let cert_id_of_sc sc =
  let c = cert_of_sc sc in
  subject_hash_of_sc sc, c.tbsCertificate.subjectPublicKeyInfo

let parse_smart_cert trusted_cert input =
  let saved_offset = PTypes.parse_save_offset input in
  let cert = parse_certificate input in
  match PTypes.parse_raw_value saved_offset input with
  | None -> sc_of_cert input.Parsifal.cur_name trusted_cert cert
  | Some raw_value -> sc_of_raw_value_and_cert input.Parsifal.cur_name trusted_cert raw_value cert

let sc_of_cert_in_hs_msg trusted_cert name i = function
  | PTypes.Parsed (raw_opt, parsed_c) ->
    { name; trusted_cert;
      raw_value = raw_opt; cert_hash = None;
      parsed_cert = Some parsed_c; pos_in_hs_msg = Some i;
      subject_hash = None; issuer_hash = None;
      issued_certs = Hashtbl.create 10;
    }
  | PTypes.Unparsed raw ->
    { name; trusted_cert;
      raw_value = Some raw; cert_hash = None;
      parsed_cert = None; pos_in_hs_msg = Some i;
      subject_hash = None; issuer_hash = None;
      issued_certs = Hashtbl.create 10;
    }



(**************)
(* cert_store *)
(**************)

type cert_store = {
  by_subject_hash : (string, smart_certificate) Hashtbl.t;
  by_hash : (string, smart_certificate) Hashtbl.t;
}

let mk_cert_store n = {
  by_subject_hash = Hashtbl.create n;
  by_hash = Hashtbl.create n;
}

let add_to_store store sc =
  let h = hash_of_sc sc in
  if not (Hashtbl.mem store.by_hash h) then begin
    let s_h = subject_hash_of_sc sc in
    Hashtbl.replace store.by_hash h sc;
    Hashtbl.add store.by_subject_hash s_h sc
  end

let find_by_subject_hash store s_h =
  Hashtbl.find_all store.by_subject_hash s_h

let find_trusted_by_subject_hash store s_h =
  List.filter (fun sc -> sc.trusted_cert) (Hashtbl.find_all store.by_subject_hash s_h)

let is_trusted store ext_sc =
  try
    let h = hash_of_sc ext_sc in
    let sc = Hashtbl.find store.by_hash h in
    sc.trusted_cert
  with Not_found -> false

let store_iter f store = Hashtbl.iter (fun _ -> f) store.by_hash



(******************************)
(* Chain validation functions *)
(******************************)

type validation_error =
| DNMismatch
| KIMismatch
| SKINotFound
| SerialNumberMismatch
| NotaCA
| InvalidSignature
| AlgorithmMismatch
| UnknownSignature

let string_of_validation_error = function
  | DNMismatch -> "subject_cert.issuer <> issuer_cert.subject"
  | KIMismatch -> "subject_cert.AKI.KI <> issuer_cert.SKI"
  | SKINotFound -> "subject_cert.AKI contains a KI, but issuer_cert has no SKI"
  | SerialNumberMismatch -> "subject_cert.AKI.serialNumber <> issuer_cert.serialNumber"
  | NotaCA -> "Issuer is not a CA"
  | InvalidSignature -> "Invalid signature"
  | AlgorithmMismatch -> "subject_cert.signature_algorithm does not match issuer_cert.public_key"
  | UnknownSignature -> "Unknown signature algorithm"


(* "Unit" test concerning *)

let check_dns issuer subject =
  if subject.tbsCertificate.issuer <> issuer.tbsCertificate.subject
  then Some DNMismatch
  else None

let check_key_identifier issuer subject =
  match get_extn_by_id [85;29;35] subject, get_extn_by_id [85;29;14] issuer with
  | Some (AuthorityKeyIdentifier {keyIdentifier = Some aki}), Some (SubjectKeyIdentifier ski)
    -> if ski <> aki then Some KIMismatch else None
  | Some (AuthorityKeyIdentifier {keyIdentifier = Some _}), None
    -> Some SKINotFound
  | _ -> None

let check_aki_serial issuer subject =
  match get_extn_by_id [85;29;35] subject with
  | Some (AuthorityKeyIdentifier {authorityCertIssuer = Some _;
				  authorityCertSerialNumber = Some sn}) ->
    if sn <> issuer.tbsCertificate.serialNumber
    then Some SerialNumberMismatch
    else None
  | _ -> None

let check_issuer_ca issuer _ =
  match issuer.tbsCertificate.version, get_extn_by_id [85;29;19] issuer with
  | None, _ -> None (* TODO: reject v1 certs? *)
  | _, Some (BasicConstraints {cA = Some true}) -> None
  | _, _ -> Some NotaCA

let check_signature issuer subject =
  match subject.tbsCertificate_raw,
    issuer.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey,
    subject.signatureValue with
    | Some m, RSA {p_modulus = n; p_publicExponent = e}, RSASignature s ->
      if (try Pkcs1.raw_verify 1 m s n e with Pkcs1.PaddingError -> false)
      then None
      else Some InvalidSignature
    | _, RSA _, _ | _, _, RSASignature _ -> Some AlgorithmMismatch
    | _, _, _ -> Some UnknownSignature

let link_check_list = [check_dns; check_key_identifier; check_aki_serial; check_issuer_ca; check_signature]


let check_link issuer subject =
  let handle_check check_fun result =
    match check_fun issuer subject with
    | None -> result
    | Some err -> err::result
  in
  List.rev (List.fold_right handle_check link_check_list [])

let check_link_bool issuer subject =
  let rec handle_checks issuer subject = function
    | [] -> true
    | check_fun::fs -> match check_fun issuer subject with
      | None -> handle_checks issuer subject fs
      | Some _ -> false
  in
  handle_checks issuer subject link_check_list


let sc_check_link issuer subject =
  let s_h = hash_of_sc subject in
  try Hashtbl.find issuer.issued_certs s_h
  with Not_found ->
    let res = check_link_bool (cert_of_sc issuer) (cert_of_sc subject) in
    Hashtbl.replace issuer.issued_certs s_h res;
    res



(**********************)
(* Certificate chains *)
(**********************)

(* TODO: add support for validity and revocation? *)
type cert_chain = {
  chain : smart_certificate list;
  unused_certs : smart_certificate list;
  complete : bool;
  trusted : bool;
  ordered : bool;
}


let print_certlist prefix cs =
  let print_line sc = match sc.pos_in_hs_msg, cert_of_sc sc with
    | None, c -> print_endline (prefix ^ "-: " ^ (string_of_distinguishedName c.tbsCertificate.subject))
    | Some i, c -> print_endline (prefix ^ (string_of_int i) ^ ": " ^ (string_of_distinguishedName c.tbsCertificate.subject))
  in List.iter print_line cs


let is_root_included = function
  | [] -> failwith "Should not happen"
  | sc::_ -> sc.pos_in_hs_msg <> None

let n_transvalid c =
  if c.complete
  then List.length (List.filter (fun sc -> sc.pos_in_hs_msg = None) (List.tl c.chain))
  else 0


let rate_chain c = match c, n_transvalid c with
    | { complete = true; trusted = true; ordered = true; unused_certs = []; }, 0    -> "A"
    | { complete = true; trusted = true; ordered = true; unused_certs = _::_; }, 0  -> "B"
    | { complete = true; trusted = true; ordered = false }, 0                       -> "C"
    | { complete = true; trusted = true }, _                                        -> "D"

    | { complete = true; trusted = false; ordered = true; unused_certs = []; }, 0   -> "C"
    | { complete = true; trusted = false; ordered = true; unused_certs = _::_; }, 0 -> "D"
    | { complete = true; trusted = false; ordered = false }, 0                      -> "D"
    | { complete = true; trusted = false }, _                                       -> "E"

    | { complete = false }, _                                                       -> "F"

let rate_and_sort_chains cs =
  let compare_chains (g1, c1) (g2, c2) =
    compare
      (g1, List.length c1.chain, not (is_root_included c1.chain))
      (g2, List.length c2.chain, not (is_root_included c2.chain))
  in
  List.sort compare_chains (List.map (fun c -> rate_chain c, c) cs)


let print_chain = function
  | { chain; unused_certs = []; complete = true; trusted; ordered; } ->
    Printf.printf "Perfect %s chain (%d cert(s), root %s, %s)\n"
      (if ordered then "ordered" else "unordered") (List.length chain)
      (if is_root_included chain then "included" else "not included")
      (if trusted then "trusted" else "not trusted");
    print_certlist "  " (List.rev chain)

  | { chain; unused_certs; complete = true; trusted; ordered; } ->
    Printf.printf "Complete %s chain (%d cert(s), %d cert(s) unused, root %s, %s)\n"
      (if ordered then "ordered" else "unordered") (List.length chain) (List.length unused_certs)
      (if is_root_included chain then "included" else "not included")
      (if trusted then "trusted" else "not trusted");
    print_certlist "  " (List.rev chain);
    print_certlist "  [UNUSED] " unused_certs

  | { chain; unused_certs; complete = false; trusted; ordered; } ->
    Printf.printf "Incomplete %s chain (%d cert(s), %d cert(s) unused, %s)\n"
      (if ordered then "ordered" else "unordered") (List.length chain) (List.length unused_certs)
      (if trusted then "trusted" else "not trusted");
    print_certlist "  " (List.rev chain);
    print_certlist "  [UNUSED] " unused_certs



(* check_rfc_certchain is a _simple_ function to validate a chain,
   according to a strict interpretation of the RFC (certs must be
   ordered) *)
let check_rfc_certchain hs_msg_certs store =
  let rec bottom_up unused_certs last chain = function
    | [] ->
      if sc_check_link last last
      then { chain = last::chain; unused_certs = unused_certs;
	     complete = true; ordered = true;
	     trusted = is_trusted store last; }
      else begin
	let acceptable_issuers =
	  List.filter
	    (fun sc -> sc_check_link sc last)
	    (find_trusted_by_subject_hash store (issuer_hash_of_sc last))
	in
	match acceptable_issuers with
	| [] -> { chain = last::chain; unused_certs = unused_certs;
		  complete = false;
		  trusted = false; ordered = true; }
	| ca::_ -> { chain = ca::last::chain; unused_certs = unused_certs;
		     complete = true;
		     trusted = true; ordered = true }
      end
    | (next::remaining) as next_certs ->
      let next_hash = hash_of_sc next in
      if not (List.mem next_hash (List.map hash_of_sc (last::chain))) && sc_check_link next last
      then bottom_up unused_certs next (last::chain) remaining
      else bottom_up (next_certs@unused_certs) last chain []
  in
  match hs_msg_certs with
  | c::cs -> bottom_up [] c [] cs
  | [] -> { chain = []; unused_certs = [];
	    complete = false;
	    trusted = false; ordered = false; }


(* This function is more generic, and allows to build unordered or
   even transvalid chains *)
let build_certchain hs_msg_certs store =

  let rec bottom_up ordered last chain next_certs =

    (* First, we check wether we have hit a self-signed cert *)
    if sc_check_link last last
    then [ { chain = last::chain; unused_certs = next_certs;
	     complete = true; ordered = ordered;
	     trusted = last.trusted_cert || is_trusted store last; } ]

    else begin
      (* Else, we need to find candidates for the next link, starting with
	 certificates present in next_certs, then moving on with CA roots,
	 and ending with other CAs we might know. *)

      let rec prepare_inmsg_candidates is_ordered previous_certs accu = function
	| [] -> accu
	| c::cs ->
	  let new_previous_certs = (c::previous_certs) in
	  let c_hash = hash_of_sc c in
	  if subject_hash_of_sc c = issuer_hash_of_sc last &&
	    not (List.mem c_hash (List.map hash_of_sc (last::chain))) &&
	    not (List.mem c_hash (List.map hash_of_sc previous_certs))
	  then begin
	    let new_accu = (is_ordered, c, List.rev_append previous_certs cs)::accu in
	    prepare_inmsg_candidates false new_previous_certs new_accu cs
	  end else prepare_inmsg_candidates false new_previous_certs accu cs
      in

      let rec prepare_external_cas is_ordered rem_certs accu = function
	| [] -> accu
	| sc::scs ->
	  let h = hash_of_sc sc in
	  let new_accu =
	    if not (List.mem h (List.map (fun (_, c, _) -> hash_of_sc c) accu)) &&
              not (List.mem h (List.map hash_of_sc (last::chain))) &&
	      not (List.mem (cert_id_of_sc sc) (List.map cert_id_of_sc (last::chain)))
	    then (is_ordered, sc, rem_certs)::accu
	    else accu
	  in prepare_external_cas is_ordered rem_certs new_accu scs
      in

      let c1 = prepare_inmsg_candidates ordered [] [] next_certs in
      let possible_issuers = find_by_subject_hash store (issuer_hash_of_sc last) in
      let trusted_roots, other_cas = List.partition (fun sc -> sc.trusted_cert) possible_issuers in
      let c2 = prepare_external_cas ordered next_certs c1 trusted_roots in
      let candidates = prepare_external_cas false next_certs c2 other_cas in

      let acceptable_issuers = List.filter (fun (_, sc, _) -> sc_check_link sc last) candidates in
      match acceptable_issuers with
      (* If no acceptable issuer has been found, this branch is an incomplete chain *)
      | [] -> [ { chain = last::chain; unused_certs = next_certs;
		  complete = false; trusted = false; ordered = ordered; } ]
      | _ -> List.flatten (List.map (fun (o, n, rems) -> bottom_up o n (last::chain) rems) acceptable_issuers)
    end
  in
  match hs_msg_certs with
  | c::cs -> bottom_up true c [] cs
  | [] -> []
