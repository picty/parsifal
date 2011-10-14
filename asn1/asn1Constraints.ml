(* Constrained parsing *)

open Asn1
open Asn1.Asn1EngineParams
open Asn1.Engine

type asn1_constraint = 
  | Anything
  | Simple_cons of (asn1_class * bool * int * string * (parsing_state -> asn1_content))
  | Complex_cons of (asn1_class -> bool -> int -> (string * (parsing_state -> asn1_content)) option)

type number_constraint =
  | AlwaysOK
  | Exactly of int * severity
  | AtLeast of int * severity
  | AtMost of int * severity
  | Between of int * int * severity

type ('a, 'b) alternative =
  | Left of 'a
  | Right of 'b

type sequence_constraint = {
  severity_if_too_many_objects : severity;
  constraint_list : (asn1_constraint * severity) list
}

let common_constrained_parse cons pstate =
  if eos pstate then Left (TooFewObjects None) else begin
    let (c, isC, t) = extract_header pstate in
    let name_and_fun = match cons with
      | Anything ->
      Right (string_of_header_pretty c isC t, choose_parse_fun pstate c isC t)

      | Simple_cons (c', isC', t', name, f) when c = c' && isC = isC' && t = t' ->
	Right (name, f)
      | Simple_cons (c', isC', t', _, _) ->    
	Left (UnexpectedHeader ((c, isC, t), Some (c', isC', t')))

      | Complex_cons get_f ->
	match get_f c isC t with
	  | None -> Left (UnexpectedHeader ((c, isC, t), None))
	  | Some (name, f) -> Right (name, f)
    in
    match name_and_fun with
      | Left err -> Left err
      | Right (name, parse_fun) ->
	extract_length pstate name;
	let content = parse_fun pstate in
	go_up pstate;
	Right {a_class = c; a_tag = t; a_content = content; a_name = name}
  end


let constrained_parse_opt cons pstate : asn1_object option =
  let res = common_constrained_parse cons pstate in
  match res with
    | Left _ -> None
    | Right x -> Some x

let constrained_parse cons pstate : asn1_object =
  let res = common_constrained_parse cons pstate in
  match res with
    | Left err -> raise (ParsingError (err, S_Fatal, pstate))
    | Right x -> x


let rec parse_sequenceof cons n pstate =
  
  let rec parse_aux n =
    if eos pstate
    then [], n
    else 
      let next = constrained_parse cons pstate in
      let tail, len = parse_aux (n + 1) in
      next::tail, len
  in
  let res, res_len = parse_aux 0 in begin
    match n with
      | AlwaysOK -> ()
      | Exactly (num, sev) ->
	if num <> res_len
	then emit (WrongNumberOfObjects (res_len, num)) sev pstate
	
      | AtLeast (num, sev) ->
	if num > res_len
	then emit (TooFewObjects (Some (res_len, num))) sev pstate
	
      | AtMost (num, sev) ->
	if num < res_len
	then emit (TooManyObjects (Some (res_len, num))) sev pstate
	  
      | Between (n1, n2, sev) ->
	if n1 > res_len
	then emit (TooFewObjects (Some (res_len, n1))) sev pstate;
	if n2 < res_len 
	then emit (TooManyObjects (Some (res_len, n2))) sev pstate
  end;
  Constructed res

	
let rec parse_constrained_sequence conss pstate =

  let rec parse_aux cons_list =
    match cons_list with
      | [] -> 
	if not (eos pstate)
	then emit (TooManyObjects None) conss.severity_if_too_many_objects pstate;
	[]

      | (cons, sev)::r ->
	if eos pstate then begin
	  if sev <> S_OK  then emit (TooFewObjects None) sev pstate;
	  parse_aux r
	end else begin
	  match common_constrained_parse cons pstate with
	    | Left err ->
	      if sev <> S_OK then emit err sev pstate;
	      parse_aux r
	    | Right next -> next::(parse_aux r)
	end
  in
  Constructed (parse_aux conss.constraint_list)


let bool_cons = Simple_cons (C_Universal, false, 1, "Boolean", der_to_boolean)
let int_cons = Simple_cons (C_Universal, false, 2, "Integer", der_to_int)
let bitstring_cons = Simple_cons (C_Universal, false, 3, "Bit String", der_to_bitstring 54)
let octetstring_cons = Simple_cons (C_Universal, false, 4, "Octet String", der_to_octetstring 54)
let null_cons = Simple_cons (C_Universal, false, 5, "Null", der_to_null)
let oid_cons = Simple_cons (C_Universal, false, 6, "OId", der_to_oid)
let printablestring_cons = Simple_cons (C_Universal, false, 19, "Printable String", der_to_octetstring 54)
let ia5string_cons = Simple_cons (C_Universal, false, 22, "IA5 String", der_to_octetstring 54)

let seqOf_cons name cons n = Simple_cons (C_Universal, true, 16, name, parse_sequenceof cons n)
let setOf_cons name cons n = Simple_cons (C_Universal, true, 17, name, parse_sequenceof cons n)
let custom_seq_cons c t name conss = Simple_cons (c, true, t, name, parse_constrained_sequence conss)


let directory_name_cons =
  let aux c isC t =
    if c = C_Universal && not isC && (List.mem t [12; 19; 20; 28; 30])
    then Some ("Time", der_to_octetstring 54)
    else None
  in Complex_cons aux

(* TODO: Reorganise this stuff *)

let pkcs1_RSA_private_key = seqOf_cons "RSA Private Key" int_cons (Exactly (9, S_SpecFatallyViolated))
let pkcs1_RSA_public_key = seqOf_cons "RSA Public Key" int_cons (Exactly (2, S_SpecFatallyViolated))


let x509_version_cons = Simple_cons (C_ContextSpecific, true, 0, "Version", parse_sequenceof int_cons (Exactly (1, S_SpecFatallyViolated)))
let x509_algoId_cons = custom_seq_cons C_Universal 16 "Algorithm identifier"
  { severity_if_too_many_objects = S_SpecFatallyViolated;
    constraint_list = [(oid_cons, S_SpecFatallyViolated); (Anything, S_SpecLightlyViolated)] }
let x509_atv_cons = custom_seq_cons C_Universal 16 "ATV"
  { severity_if_too_many_objects = S_SpecFatallyViolated;
    constraint_list = [(oid_cons, S_SpecFatallyViolated); (Anything, S_SpecFatallyViolated)] }
let x509_rdn_cons = setOf_cons "Relative DN" x509_atv_cons (AtLeast (1, S_SpecLightlyViolated))
let x509_dn_cons = seqOf_cons "Distinguished Name" x509_rdn_cons (AtLeast (1, S_SpecLightlyViolated))

let x509_time_cons =
  let aux c isC t =
    if c = C_Universal && not isC && (t = 23 || t = 24)
    then Some ("Time", der_to_octetstring 54)
    else None
  in Complex_cons aux

let x509_validity_cons = seqOf_cons "Validity" x509_time_cons (Exactly (2, S_SpecFatallyViolated))

let x509_subject_pubkey_cons = custom_seq_cons C_Universal 16
  "Subject Public Key"
  { severity_if_too_many_objects = S_SpecFatallyViolated;
    constraint_list = [(x509_algoId_cons, S_SpecFatallyViolated); (bitstring_cons, S_SpecFatallyViolated)] }

let x509_extension_cons = custom_seq_cons C_Universal 16
  "Extension"
  { severity_if_too_many_objects = S_SpecFatallyViolated;
    constraint_list = [(oid_cons, S_SpecFatallyViolated);
		       (bool_cons, S_OK);
		       (octetstring_cons, S_SpecFatallyViolated)] }

let x509_extensions_cons =
  Simple_cons (C_ContextSpecific, true, 3, "Extensions container",
	       parse_sequenceof (seqOf_cons "Extensions" x509_extension_cons AlwaysOK) (Exactly (1, S_SpecFatallyViolated)))

let x509_tbsCertificate_cons = custom_seq_cons C_Universal 16
  "tbsCertificate"
  { severity_if_too_many_objects = S_SpecFatallyViolated;
    constraint_list = [(x509_version_cons, S_OK);
		       (int_cons, S_SpecFatallyViolated);
		       (x509_algoId_cons, S_SpecFatallyViolated);
		       (x509_dn_cons, S_SpecFatallyViolated);
		       (x509_validity_cons, S_SpecFatallyViolated);
		       (x509_dn_cons, S_SpecFatallyViolated);
		       (x509_subject_pubkey_cons, S_SpecFatallyViolated);
   (*   (bitstring_cons, S_OK);
	(octetstring_cons, S_OK);*)
		       (x509_extensions_cons, S_OK)] }

let x509_certificate_cons = custom_seq_cons C_Universal 16
  "Certificate"
  { severity_if_too_many_objects = S_SpecFatallyViolated;
    constraint_list = [(x509_tbsCertificate_cons, S_SpecFatallyViolated);
		       (x509_algoId_cons, S_SpecFatallyViolated);
		       (bitstring_cons, S_SpecFatallyViolated)] }

(*
let extract_tbs cert =
  match decapsulate cert with
    | (C_Universal, 16, Constructed tbs)::
	(C_Universal, 16, Constructed _)::
	(C_Universal, 3, BitString _)::[]
      -> tbs
    | _ -> failwith "Invalid certificate"
      
let extract_dns tbs =
  match tbs with
    | (C_ContextSpecific, 0, Constructed _)::
	(C_Universal, 2, Integer _)::
	(C_Universal, 16, Constructed _)::
	(C_Universal, 16, Constructed i)::
	(C_Universal, 16, Constructed _)::
	(C_Universal, 16, Constructed s)::
	(C_Universal, 16, Constructed _)::r
      -> i, s
    | _ -> failwith "Invalid certificate"

(*let exts = List.hd (List.rev (tbs));;
let ext_list = decapsulate (List.hd (decapsulate exts))
let oid_of_ext = function
  | (C_Universal, 16, Constructed ((C_Universal, 6, OId l)::_)) -> l;;
List.map oid_of_ext ext_list;;
*)
*)
