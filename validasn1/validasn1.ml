(* Constrained parsing *)

open Asn1
open Asn1Parser
open Asn1Parser.Asn1EngineParams
open Asn1Parser.Engine

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

let common_constrained_parse cons pstate =
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
      Right {a_class = c; a_tag = t; a_content = content; a_name = name}


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
	then emit (TooFewObjects (res_len, num)) sev pstate
	
      | AtMost (num, sev) ->
	if num < res_len
	then emit (TooManyObjects (res_len, num)) sev pstate
	  
      | Between (n1, n2, sev) ->
	if n1 > res_len
	then emit (TooFewObjects (res_len, n1)) sev pstate;
	if n2 < res_len 
	then emit (TooManyObjects (res_len, n2)) sev pstate
  end;
  Constructed res

	
let rec parse_constrained_sequence (conss : (asn1_constraint * bool) list) pstate =

  let rec parse_aux () =
    match conss with
      | [] when eos  ->
	failwith ("Too many objects in the constructed object" ^
		     " at offset " ^ (string_of_int (new_base + offset)))
      | [] -> []
      | (_, false)::r when offset = len -> parse_aux offset r
      | (_, true)::r when offset = len ->
	failwith ("Too few objects in the constructed object" ^
		     " at offset " ^ (string_of_int (new_base + offset)))
      | (cons, false)::r -> begin
	match constrained_parse_opt cons substring new_base offset with
	  | None -> parse_aux offset r
	  | Some (next, new_offset) -> next::(parse_aux new_offset r)
      end
      | (cons, true)::r -> 
	let (next, new_offset) = constrained_parse cons substring new_base offset in
	next::(parse_aux new_offset r)
  in
  Constructed (parse_aux 0 conss)
    
    
let bool_cons = Simple_cons (C_Universal, false, 1, der_to_boolean)
let int_cons = Simple_cons (C_Universal, false, 2, der_to_int)
let bitstring_cons = Simple_cons (C_Universal, false, 3, der_to_bitstring)
let octetstring_cons = Simple_cons (C_Universal, false, 4, der_to_octetstring)
let oid_cons = Simple_cons (C_Universal, false, 6, der_to_oid)
let seqOf_cons cons n = Simple_cons (C_Universal, true, 16, parse_sequenceof cons n)
let setOf_cons cons n = Simple_cons (C_Universal, true, 17, parse_sequenceof cons n)
let custom_seq_cons c t conss = Simple_cons (c, true, t, parse_constrained_sequence conss)
  
let pkcs1_RSA_private_key = seqOf_cons int_cons (Exactly 9)
let pkcs1_RSA_public_key = seqOf_cons int_cons (Exactly 2)
  
  
let x509_version_cons = Simple_cons (C_ContextSpecific, true, 0, parse_sequenceof int_cons (Exactly 1))
let x509_algoId_cons = custom_seq_cons C_Universal 16 [(oid_cons, true); (Anything, false)]
let x509_atv_cons = custom_seq_cons C_Universal 16 [(oid_cons, true); (Anything, true)]
let x509_rdn_cons = setOf_cons x509_atv_cons (AtLeast 1)
let x509_dn_cons = seqOf_cons x509_rdn_cons AlwaysOK
  
let x509_time_cons =
  let aux c isC t =
    if c = C_Universal && not isC && (t = 23 || t = 24)
    then Some (der_to_octetstring)
    else None
  in Complex_cons aux
  
let x509_validity_cons = seqOf_cons x509_time_cons (Exactly 2)
  
let x509_subject_pubkey_cons = custom_seq_cons C_Universal 16
  [(x509_algoId_cons, true);
   (bitstring_cons, true)]
  
let x509_extension_cons = custom_seq_cons C_Universal 16
  [(oid_cons, true);
   (bool_cons, false);
   (octetstring_cons, true)]
  
let x509_extensions_cons =
  Simple_cons (C_ContextSpecific, true, 3,
	       parse_sequenceof (seqOf_cons x509_extension_cons AlwaysOK) (Exactly 1))
    
let x509_tbsCertificate_cons = custom_seq_cons C_Universal 16
  [(x509_version_cons, false);
   (int_cons, true);
   (x509_algoId_cons, true);
   (x509_dn_cons, true);
   (x509_validity_cons, true);
   (x509_dn_cons, true);
   (x509_subject_pubkey_cons, true);
     (*   (bitstring_cons, false);
	  (octetstring_cons, false);*)
   (x509_extensions_cons, false)]
  
let x509_certificate_cons = custom_seq_cons C_Universal 16
  [(x509_tbsCertificate_cons, true);
   (x509_algoId_cons, true);
   (bitstring_cons, true)]
  
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
