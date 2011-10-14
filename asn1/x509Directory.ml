open Asn1Constraints
open Asn1.Asn1EngineParams
open X509

(* RSA *)

let sha1WithRSAEncryption_oid = [42;840;113549;1;1;5]
let rsaEncryption_oid = [42;840;113549;1;1;1]

let add_rsa_stuff () =
  Hashtbl.add name_directory sha1WithRSAEncryption_oid "sha1WithRSAEncryption";
  Hashtbl.add object_directory (SigAlgo, sha1WithRSAEncryption_oid) (null_obj_cons, S_Benign);

  Hashtbl.add name_directory rsaEncryption_oid "rsaEncryption";
  Hashtbl.add object_directory (PubKeyAlgo, rsaEncryption_oid) (null_obj_cons, S_Benign);;



(* DN and ATVs *)

let add_atv oid name initial cons sev =
  Hashtbl.add name_directory oid name;
  match initial with
    | None -> ()
    | Some s -> Hashtbl.add initial_directory oid s;
  Hashtbl.add object_directory (ATV, oid) (cons, sev)


let add_standard_atv () =
  add_atv [85;4;41] "name" None directory_name_cons S_Benign;
  add_atv [85;4;4] "surname" None directory_name_cons S_Benign;
  add_atv [85;4;42] "givenName" None directory_name_cons S_Benign;
  add_atv [85;4;43] "initials" None directory_name_cons S_Benign;
  add_atv [85;4;44] "genrationQualifier" None directory_name_cons S_Benign;
  add_atv [85;4;3] "commonName" (Some "CN") directory_name_cons S_Benign;
  add_atv [85;4;7] "locality" (Some "L") directory_name_cons S_Benign;
  add_atv [85;4;8] "state" (Some "S") directory_name_cons S_Benign;
  add_atv [85;4;10] "organization" (Some "O") directory_name_cons S_Benign;
  add_atv [85;4;11] "organizationalUnit" (Some "OU") directory_name_cons S_Benign;
  add_atv [85;4;12] "title" None directory_name_cons S_Benign;
  add_atv [85;4;46] "dnQualifier" None printablestring_cons S_Benign;
  (* TODO: Add constraint on length ? *)
  add_atv [85;4;6] "country" (Some "C") printablestring_cons S_Benign;
  add_atv [85;4;5] "serial" None printablestring_cons S_Benign;
  add_atv [85;4;65] "pseudonym" None directory_name_cons S_Benign;
  add_atv [9;2342;19200300;100;1;25] "domainComponent" None ia5string_cons S_Benign;
  add_atv [42;840;113549;1;9;1] "emailAddress" None ia5string_cons S_Benign;;



let _ =
  add_rsa_stuff ();
  add_standard_atv ();;
