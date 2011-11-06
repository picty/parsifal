(* type dsa_public_key = {dsa_p : string; dsa_q : string; dsa_g : string; dsa_Y : string}
type rsa_public_key = {rsa_n : string; rsa_e : string}

type public_key =
  | PK_WrongPKInfo
  | PK_DSA of dsa_public_key
  | PK_RSA of rsa_public_key
  | PK_Unparsed of string
*)



(*
(* RSA *)

let sha1WithRSAEncryption_oid = [42;840;113549;1;1;5]
let rsaEncryption_oid = [42;840;113549;1;1;1]

let parse_rsa_public_key _ s =
  let rsa_from_list = function
    | [n; e] -> PK_RSA {rsa_n = n; rsa_e = e}
    | _ -> PK_Unparsed s
  in
  let rsa_constraint = seqOf_cons rsa_from_list "RSA Public Key" int_cons (Exactly (2, s_specfatallyviolated)) in
  let pstate = pstate_of_string "RSA Public Key" s in
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


*)


(*

let pkcs1_RSA_private_key = seqOf_cons mk_object "RSA Private Key" int_cons (Exactly (9, s_specfatallyviolated))
let pkcs1_RSA_public_key = seqOf_cons mk_object "RSA Public Key" int_cons (Exactly (2, s_specfatallyviolated))

*)


(*
  let new_indent = indent ^ !PrinterLib.indent in
    (match pki.public_key with
      | PK_WrongPKInfo ->
	indent ^ "Wrong Public Key Info:\n" ^
	  new_indent ^ "Public key algorithm:\n" ^ (string_of_oid_object new_indent pki.pk_algo)
      | PK_DSA {dsa_p; dsa_q; dsa_g; dsa_Y} ->
	indent ^ "DSA Public Key:\n" ^
	  new_indent ^ "p: 0x" ^ (hexdump dsa_p) ^ "\n" ^
	  new_indent ^ "q: 0x" ^ (hexdump dsa_q) ^ "\n" ^
	  new_indent ^ "g: 0x" ^ (hexdump dsa_g) ^ "\n" ^
	  new_indent ^ "Y: 0x" ^ (hexdump dsa_Y) ^ "\n"
      | PK_RSA {rsa_n; rsa_e} ->
	indent ^ "RSA Public Key:\n" ^
	  new_indent ^ "n: 0x" ^ (hexdump rsa_n) ^ "\n" ^
	  new_indent ^ "e: 0x" ^ (hexdump rsa_e) ^ "\n"
      | PK_Unparsed s ->
	indent ^ "Public key:\n" ^
	  new_indent ^ "Public key algorithm:\n" ^ (string_of_oid_object new_indent pki.pk_algo) ^
	  new_indent ^ "Value: [HEX]" ^ hexdump (s) ^ "\n")
*)



(*
type dsa_signature = {dsa_r : string; dsa_s : string}

type signature =
  | Sig_WrongSignature
  | Sig_DSA of dsa_signature
  | Sig_RSA of string
  | Sig_Unparsed of string

let empty_signature = Sig_WrongSignature

let string_of_signature indent sign =
  match sign with
    | Sig_WrongSignature -> indent ^ "Wrong Signature\n"
    | Sig_DSA {dsa_r; dsa_s} ->
      indent ^ "r: " ^ (hexdump dsa_r) ^ "\n" ^
	indent ^ "s: " ^ (hexdump dsa_s) ^ "\n"
    | Sig_RSA s ->
      indent ^ "s: " ^ (hexdump s) ^ "\n"
    | Sig_Unparsed s -> indent ^ "[HEX]" ^ (hexdump s) ^ "\n"


  *)



(*

    (* cert.tbs.public_key_info.pk_algo *)
    begin
      match cert.tbs.pk_info.public_key with
	| PK_DSA {dsa_p; dsa_q; dsa_g; dsa_Y} ->
	  Hashtbl.replace dict "key_type" (V_String "DSA");
	  Hashtbl.replace dict "p" (V_Bigint dsa_p);
	  Hashtbl.replace dict "q" (V_Bigint dsa_q);
	  Hashtbl.replace dict "g" (V_Bigint dsa_g);
	  Hashtbl.replace dict "Y" (V_Bigint dsa_Y)
	| PK_RSA {rsa_n; rsa_e} ->
	  Hashtbl.replace dict "key_type" (V_String "RSA");
	  Hashtbl.replace dict "n" (V_Bigint rsa_n);
	  Hashtbl.replace dict "e" (V_Bigint rsa_e)
	| PK_WrongPKInfo ->
	  Hashtbl.replace dict "key_type" (V_String "WrongPKInfo");
	| PK_Unparsed _ ->
	  Hashtbl.replace dict "key_type" (V_String "UnparsedPKInfo");
    end;

    (* cert_sig_algo *)
    begin
      match cert.signature with
	| Sig_DSA {dsa_r; dsa_s} ->
	  Hashtbl.replace dict "sig_type" (V_String "DSA");
	  Hashtbl.replace dict "r" (V_Bigint dsa_r);
	  Hashtbl.replace dict "s" (V_Bigint dsa_s)
	| Sig_RSA rsa_s ->
	  Hashtbl.replace dict "sig_type" (V_String "RSA");
	  Hashtbl.replace dict "s" (V_Bigint rsa_s)
	| Sig_WrongSignature ->
	  Hashtbl.replace dict "key_type" (V_String "WrongSignature");
	| Sig_Unparsed _ ->
	  Hashtbl.replace dict "key_type" (V_String "UnparsedSignature");
    end	;

*)
