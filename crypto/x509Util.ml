open X509


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
