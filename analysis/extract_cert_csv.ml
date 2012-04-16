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

let extract_pk pki =
  match pki.pk_algo, pki.public_key with
    | _, V_Dict d ->
      begin
	try
	  if eval_as_string (d --> "type") = "RSA"
	  then begin
	    let n = eval_as_string (d --> "n") in
	    if String.length n > 0 && n.[0] = '\x00'
	    then ("RSA", hexdump (Crypto.sha1sum n), (String.length n) * 8 - 8)
	    else ("RSA", hexdump (Crypto.sha1sum n), (String.length n) * 8)
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

let print_cert _id cert =
  Printf.printf "Version=%d\n" (pop_option cert.tbs.version 1);
  Printf.printf "Serial=%s\n" (hexdump cert.tbs.serial);
  Printf.printf "NotBefore=%s\n" (string_of_dt cert.tbs.validity.not_before);
  Printf.printf "NotAfter=%s\n" (string_of_dt cert.tbs.validity.not_after);
  Printf.printf "Duration=%d\n" (extract_duration cert.tbs.validity);
  Printf.printf "Issuer=%s\n" (X509DN.short_display cert.tbs.issuer);
  Printf.printf "Subject=%s\n" (X509DN.short_display cert.tbs.subject);
  let (t, h, sz) = extract_pk cert.tbs.pk_info in
  Printf.printf "PkType=%s\n" t;
  Printf.printf "PkModHash=%s\n" h;
  Printf.printf "PkModSize=%d\n" sz;
  Printf.printf "CA=%s\n" (eval_as_string (string_of_blurry (is_ca cert)));
  let ski =
    try hexdump (eval_as_string (_get_content_extension (pop_option cert.tbs.extensions []) subjectKeyIdentifier_oid))
    with _ -> ""
  in
  Printf.printf "SKI=%s\n" ski;
  let aki_serial, aki_ki =
    try
      let aki_content = eval_as_dict (_get_content_extension (pop_option cert.tbs.extensions []) authorityKeyIdentifier_oid) in
      let serial = hash_find_default aki_content "authorityCertSerialNumber" (V_String "")
      and ki = hash_find_default aki_content "keyIdentifier" (V_String "") in
      (hexdump (eval_as_string serial), hexdump (eval_as_string ki))
    with _ -> "", ""
  in
  Printf.printf "AKI.serial=%s\n" aki_serial;
  Printf.printf "AKI.keyId=%s\n" aki_ki;
  Printf.printf "CertificatPolicies=%s\n" (String.concat ", " (extract_cert_policies cert))

let print_cert id cert =
  Printf.printf "%s:" id;
  Printf.printf "%d:" (pop_option cert.tbs.version 1);
  Printf.printf "%s:" (hexdump cert.tbs.serial);
  Printf.printf "%s:" (string_of_dt cert.tbs.validity.not_before);
  Printf.printf "%s:" (string_of_dt cert.tbs.validity.not_after);
  Printf.printf "%d:" (extract_duration cert.tbs.validity);
  Printf.printf "%s:" (X509DN.short_display cert.tbs.issuer);
  Printf.printf "%s:" (X509DN.short_display cert.tbs.subject);
  let (t, h, sz) = extract_pk cert.tbs.pk_info in
  Printf.printf "%s:" t;
  Printf.printf "%s:" h;
  Printf.printf "%d:" sz;
  Printf.printf "%s:" (eval_as_string (string_of_blurry (is_ca cert)));
  let ski =
    try hexdump (eval_as_string (_get_content_extension (pop_option cert.tbs.extensions []) subjectKeyIdentifier_oid))
    with _ -> ""
  in
  Printf.printf "%s:" ski;
  let aki_serial, aki_ki =
    try
      let aki_content = eval_as_dict (_get_content_extension (pop_option cert.tbs.extensions []) authorityKeyIdentifier_oid) in
      let serial = hash_find_default aki_content "authorityCertSerialNumber" (V_String "")
      and ki = hash_find_default aki_content "keyIdentifier" (V_String "") in
      (hexdump (eval_as_string serial), hexdump (eval_as_string ki))
    with _ -> "", ""
  in
  Printf.printf "%s:" aki_serial;
  Printf.printf "%s:" aki_ki;
  Printf.printf "%s\n" (String.concat ", " (extract_cert_policies cert))
    

let _ =
  parse_public_key := true;
  parse_extensions := true;
  try
    while true do
      try
	let line = read_line () in
	match string_split ':' line with
	  | [id; cert_pem] ->
	    let pstate = pstate_of_string (Some id) (Base64.from_raw_base64 cert_pem) in
	    let cert = X509.parse pstate
	    in print_cert id cert
	  | _ -> failwith "Shitty line"
      with
	| OutOfBounds s -> output_string stderr ("Out of bounds in " ^ s ^ ")")
	| ParsingError (err, sev, pstate) -> output_string stderr (string_of_parsing_error "Fatal" err sev pstate)
    done
  with End_of_file -> ()
