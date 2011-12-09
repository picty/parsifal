(* RSA *)

open Types
open ParsingEngine

open Asn1
open Asn1Constraints
open X509Misc
open X509PublicKey
open X509Signature


let sha1WithRSAEncryption_oid = [42;840;113549;1;1;5]
let rsaEncryption_oid = [42;840;113549;1;1;1]

let parse_rsa_public_key _ nBits s =
  let rsa_from_list = function
    | [n; e] ->
      let res = Hashtbl.create 3 in
      Hashtbl.replace res "type" (V_String "RSA");
      Hashtbl.replace res "n" (V_Bigint n);
      Hashtbl.replace res "e" (V_Bigint e);
      V_Dict res
    | _ -> V_Unit
  in
  let rsa_constraint = seqOf_cons rsa_from_list "RSA Public Key" int_cons (Exactly (2, s_specfatallyviolated)) in
  let pstate = pstate_of_string (Some "RSA Public Key") s in
  if (nBits <> 0) then asn1_emit InvalidBitStringLength None (Some "nBits should be zero") pstate;
  constrained_parse_def rsa_constraint s_specfatallyviolated V_Unit pstate

let parse_rsa_signature nBits s =
  if (nBits <> 0) then asn1_emit InvalidBitStringLength None (Some "nBits should be zero") (pstate_of_string None "");
  let res = Hashtbl.create 2 in
  Hashtbl.replace res "s" (V_Bigint s);
  V_Dict res


let _ =
  register_oid sha1WithRSAEncryption_oid "sha1WithRSAEncryption";
  Hashtbl.add object_directory (SigAlgo, sha1WithRSAEncryption_oid) (null_obj_cons, s_benign);

  register_oid rsaEncryption_oid "rsaEncryption";
  Hashtbl.add object_directory (PubKeyAlgo, rsaEncryption_oid) (null_obj_cons, s_benign);

  Hashtbl.add pubkey_directory rsaEncryption_oid parse_rsa_public_key;
  Hashtbl.add signature_directory sha1WithRSAEncryption_oid parse_rsa_signature;;

