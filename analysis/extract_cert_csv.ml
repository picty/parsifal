open Common
open Types
open ParsingEngine
open X509
open X509Validity
open X509PublicKey
open X509Extensions
open X509Misc


let string_of_dt dt =
  (string_of_int dt.year) ^ "-" ^ (string_of_int dt.month) ^ "-" ^ (string_of_int dt.day)

let nday_of_dt dt =
  dt.year * 365 + dt.month * 30 + dt.day

let extract_duration v =
  (nday_of_dt v.not_after) - (nday_of_dt v.not_before)

let mk_hash s =
  String.sub (hexdump (Crypto.sha1sum s)) 0 16

(* no =, no /, no : *)
let only_printable_and_no_special s =
  let n = String.length s in
  let res = String.create (n * 4) in
  let rec aux src dst =
    if src == n
    then String.sub res 0 dst
    else begin
      let c = s.[src] in
      let ord = int_of_char c in
      if ord >= 32 && ord < 128 && c <> ':' && c <> '/' && c <> '='
      then begin
	res.[dst] <- c;
	aux (src + 1) (dst + 1)
      end else begin
	res.[dst] <- '\\';
	res.[dst+1] <- 'x';
	res.[dst+2] <- hexa_char.[ord / 16];
	res.[dst+3] <- hexa_char.[ord mod 16];
	aux (src + 1) (dst + 4)
      end
    end
  in aux 0 0

let my_short_display dn =
  let short_of_atv atv =
    let oid_str =
      try Hashtbl.find X509DN.initial_directory atv.oo_id
      with Not_found -> Asn1.string_of_oid atv.oo_id
    and content_str = match atv.oo_content with
      | None -> ""
      | Some o -> String.concat "," (fst (Asn1.string_of_content o.Asn1.a_content))
    in "/" ^ oid_str ^ "=" ^ (only_printable_and_no_special content_str)
  in String.concat "" (List.map short_of_atv (List.flatten dn))

let extract_pk pki =
  match pki.pk_algo, pki.public_key with
    | _, V_Dict d ->
      begin
	try
	  if eval_as_string (d --> "type") = "RSA"
	  then begin
	    let n = eval_as_string (d --> "n") in
	    if String.length n > 0 && n.[0] = '\x00'
	    then ("RSA", mk_hash n, (String.length n) * 8 - 8)
	    else ("RSA", mk_hash n, (String.length n) * 8)
	  end else failwith ""
	with _ -> "Unknown", "", 0
      end
    | {oo_id = [43;14;3;2;12]}, _
    | {oo_id = [42;840;10040;4;1]}, _ -> "DSA", "", 0
    | _ -> "Unknown", "", 0


let extract_cert_policies cert =
  let rec aux = function
    | (V_Dict d)::r ->
      let id = match d --> "policyIdentifier" with
	| V_String s -> s
	| V_List oid -> String.concat "." (List.map eval_as_string oid)
	| _ -> failwith ""
      in id::(aux r)
    | _ -> []
  in
  try aux (eval_as_list (_get_content_extension (pop_option cert.tbs.extensions []) certifcatePolicies_oid))
  with _ -> []


let extract_dn dn =
  let short = my_short_display dn in
  (mk_hash short, short)



(* KU, EKU, CRLDP, AIA, SAN *)

let print_cert id cert =
  let (t, h, sz) = extract_pk cert.tbs.pk_info
  and ski =
    try hexdump (eval_as_string (_get_content_extension (pop_option cert.tbs.extensions []) subjectKeyIdentifier_oid))
    with _ -> ""
  and aki_serial, aki_ki =
    try
      let aki_content = eval_as_dict (_get_content_extension (pop_option cert.tbs.extensions [])
					authorityKeyIdentifier_oid) in
      let serial = hash_find_default aki_content "authorityCertSerialNumber" (V_String "")
      and ki = hash_find_default aki_content "keyIdentifier" (V_String "") in
      (hexdump (eval_as_string serial), hexdump (eval_as_string ki))
    with _ -> "", ""
  and (issuer_hash, issuer_short) = extract_dn cert.tbs.issuer
  and (subject_hash, subject_short) = extract_dn cert.tbs.subject
  in
  let strs = ["CertificateParsed";
	      id;
	      string_of_int (pop_option cert.tbs.version 1);
	      hexdump cert.tbs.serial;
	      string_of_dt cert.tbs.validity.not_before;
	      string_of_dt cert.tbs.validity.not_after;
	      string_of_int (extract_duration cert.tbs.validity);
	      issuer_hash;
	      subject_hash;
	      t; h; string_of_int sz;
	      eval_as_string (string_of_blurry (is_ca cert));
	      ski;
	      aki_serial; aki_ki;
	      String.concat ", " (extract_cert_policies cert)]
  in
  print_endline (String.concat ":" strs);
  print_endline ("DistinguishedNames:" ^ issuer_hash ^ ":" ^ issuer_short);
  print_endline ("DistinguishedNames:" ^ subject_hash ^ ":" ^ subject_short)
    

let _ =
  parse_public_key := true;
  parse_extensions := true;
  try
    while true do
      let line = read_line () in
      try
	match string_split ':' line with
	  | [id; cert_pem] ->
	    let pstate = pstate_of_string (Some id) (Base64.from_raw_base64 cert_pem) in
	    let cert = X509.parse pstate
	    in print_cert id cert
	  | _ -> failwith "Shitty line"
      with
	| _ -> print_endline ("CertificateUnparsed:" ^ line)
    done
  with End_of_file -> ()
