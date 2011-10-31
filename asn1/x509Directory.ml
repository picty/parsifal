open ParsingEngine
open Asn1Constraints
open Asn1.Asn1EngineParams
open X509


(* RSA *)

let sha1WithRSAEncryption_oid = [42;840;113549;1;1;5]
let rsaEncryption_oid = [42;840;113549;1;1;1]

let parse_rsa_public_key _ s =
  let rsa_from_list = function
    | [n; e] -> PK_RSA {rsa_n = n; rsa_e = e}
    | _ -> PK_Unparsed s
  in
  let rsa_constraint = seqOf_cons rsa_from_list "RSA Public Key" int_cons (Exactly (2, s_specfatallyviolated)) in
  let pstate = Asn1.Engine.pstate_of_string "RSA Public Key" s in
  constrained_parse_def rsa_constraint s_specfatallyviolated (PK_Unparsed s) pstate

let parse_rsa_sig s = Sig_RSA s

let add_rsa_stuff () =
  Hashtbl.add name_directory sha1WithRSAEncryption_oid "sha1WithRSAEncryption";
  Hashtbl.add object_directory (SigAlgo, sha1WithRSAEncryption_oid) (null_obj_cons, s_benign);

  Hashtbl.add name_directory rsaEncryption_oid "rsaEncryption";
  Hashtbl.add object_directory (PubKeyAlgo, rsaEncryption_oid) (null_obj_cons, s_benign);

  Hashtbl.add pubkey_directory rsaEncryption_oid parse_rsa_public_key;
  Hashtbl.add signature_directory sha1WithRSAEncryption_oid parse_rsa_sig;;


(* DSA *)

let dSA_oid = [42;840;10040;4;1]
(* let dSAAlgorithm_oid = [43;14;3;2;12] *)
let dsaWithSha1_oid = [42;840;10040;4;3]

let parse_dsa_public_key params s =
  let open Asn1 in
      match params with
	| Some { a_content = Constructed [ { a_content = Integer p };
					   { a_content = Integer q };
					   { a_content = Integer g } ] }
	  -> begin
	    let pstate = Engine.pstate_of_string "DSA Public Key" s in
	    match constrained_parse_opt int_cons s_specfatallyviolated pstate with
	      | Some y -> PK_DSA {dsa_p = p; dsa_q = q; dsa_g = g; dsa_Y = y}
	      | None -> PK_Unparsed s
	  end
	| _ -> PK_Unparsed s

let parse_dsa_sig str =
  let dsa_sig_from_list = function
    | [r; s] -> Sig_DSA {dsa_r = r; dsa_s = s}
    | _ -> Sig_Unparsed str
  in
  let dsa_constraint = seqOf_cons dsa_sig_from_list "DSA Signature" int_cons (Exactly (2, s_specfatallyviolated)) in
  let pstate = Asn1.Engine.pstate_of_string "DSA Public Key" str in
  constrained_parse_def dsa_constraint s_specfatallyviolated (Sig_Unparsed str) pstate

let add_dsa_stuff () =
  Hashtbl.add name_directory dSA_oid "dSA";
  Hashtbl.add object_directory (PubKeyAlgo, dSA_oid)
    (seqOf_obj_cons "DSS Params" int_obj_cons (Exactly (3, s_specfatallyviolated)),
     s_specfatallyviolated);

  Hashtbl.add name_directory dsaWithSha1_oid "dsaWithSha1";
  Hashtbl.add object_directory (PubKeyAlgo, dsaWithSha1_oid) (null_obj_cons, s_benign);

  Hashtbl.add pubkey_directory dSA_oid parse_dsa_public_key;
  Hashtbl.add signature_directory dsaWithSha1_oid parse_dsa_sig;;


(* DN and ATVs *)

let add_atv oid name initial cons sev =
  Hashtbl.add name_directory oid name;
  match initial with
    | None -> ()
    | Some s -> Hashtbl.add initial_directory oid s;
  Hashtbl.add object_directory (ATV, oid) (cons, sev)


let add_standard_atv () =
  add_atv [85;4;41] "name" None directory_name_cons s_benign;
  add_atv [85;4;4] "surname" None directory_name_cons s_benign;
  add_atv [85;4;42] "givenName" None directory_name_cons s_benign;
  add_atv [85;4;43] "initials" None directory_name_cons s_benign;
  add_atv [85;4;44] "genrationQualifier" None directory_name_cons s_benign;
  add_atv [85;4;3] "commonName" (Some "CN") directory_name_cons s_benign;
  add_atv [85;4;7] "locality" (Some "L") directory_name_cons s_benign;
  add_atv [85;4;8] "state" (Some "S") directory_name_cons s_benign;
  add_atv [85;4;10] "organization" (Some "O") directory_name_cons s_benign;
  add_atv [85;4;11] "organizationalUnit" (Some "OU") directory_name_cons s_benign;
  add_atv [85;4;12] "title" None directory_name_cons s_benign;
  add_atv [85;4;46] "dnQualifier" None printablestring_cons s_benign;
  (* TODO: Add constraint on length ? *)
  add_atv [85;4;6] "country" (Some "C") printablestring_cons s_benign;
  add_atv [85;4;5] "serial" None printablestring_cons s_benign;
  add_atv [85;4;65] "pseudonym" None directory_name_cons s_benign;
  add_atv [9;2342;19200300;100;1;25] "domainComponent" None ia5string_cons s_benign;
  add_atv [42;840;113549;1;9;1] "emailAddress" None ia5string_cons s_benign;;



let _ =
  add_rsa_stuff ();
  add_dsa_stuff ();
  add_standard_atv ();;
