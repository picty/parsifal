open Asn1Constraints
open Asn1.Asn1EngineParams
open X509

(* RSA *)

let sha1WithRSAEncryption_oid = [42;840;113549;1;1;5]
let rsaEncryption_oid = [42;840;113549;1;1;1]

let add_rsa_stuff () =
  Hashtbl.add name_directory sha1WithRSAEncryption_oid "sha1WithRSAEncryption";
  Hashtbl.add object_directory (SigAlgo, sha1WithRSAEncryption_oid) (null_obj_cons, s_benign);

  Hashtbl.add name_directory rsaEncryption_oid "rsaEncryption";
  Hashtbl.add object_directory (PubKeyAlgo, rsaEncryption_oid) (null_obj_cons, s_benign);;
  (* TODO: Add Signature / Public Key *)


(* DSA *)

let dSA_oid = [42;840;10040;4;1]
(* let dSAAlgorithm_oid = [43;14;3;2;12] *)
let dsaWithSha1_oid = [42;840;10040;4;3]

let add_dsa_stuff () =
  Hashtbl.add name_directory dSA_oid "dSA";
  Hashtbl.add object_directory (PubKeyAlgo, dSA_oid)
    (seqOf_obj_cons "DSS Params" int_obj_cons (Exactly (3, s_specfatallyviolated)),
     s_specfatallyviolated);

  Hashtbl.add name_directory dsaWithSha1_oid "dsaWithSha1";
  Hashtbl.add object_directory (PubKeyAlgo, dsaWithSha1_oid) (null_obj_cons, s_benign);;
  (* TODO: Add Signature / Public Key *)


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
