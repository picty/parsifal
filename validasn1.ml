(* Constrained parsing *)

open Asn1

type asn1_constraint = 
  | Anything
  | Simple_cons of (Asn1.asn1_class * bool * int * (string -> int -> int -> int -> Asn1.asn1_content))
  | Complex_cons of (Asn1.asn1_class -> bool -> int -> (string -> int -> int -> int -> Asn1.asn1_content) option)
      
type number_constraint =
  | AlwaysOK
  | Exactly of int
  | AtLeast of int
  | AtMost of int
  | Between of int * int
      
type parse_function =
  | Not_found of string
  | Found of (Asn1.asn1_object * int)
      
let common_constrained_parse cons str base offset =
  let ((c, isC, t), o1) = Asn1.extract_header str offset in
  let (len, o2) = Asn1.extract_length str o1 in
  match cons with
    | Anything ->
      let parse_fun = Asn1.choose_parse_fun c isC t in
      Found ((c, t, parse_fun str base o2 len), o2 + len)
    | Simple_cons (c', isC', t', f) when c = c' && isC = isC' && t = t' ->
      Found ((c, t, f str base o2 len), o2 + len)
    | Simple_cons (c', isC', t', _) ->
      Not_found ("Got " ^ (Asn1.string_of_header c isC t) ^ " while expecting " ^ (Asn1.string_of_header c' isC' t') ^
		    " at offset " ^ (string_of_int (base + offset)))
    | Complex_cons get_f ->
      match get_f c isC t with
	| None -> Not_found ("Unexpected header " ^ (Asn1.string_of_header c isC t) ^ " at offset " ^ (string_of_int (base + offset)))
	| Some f -> Found ((c, t, f str base o2 len), o2 + len)
	  
let constrained_parse_opt cons str base offset : (Asn1.asn1_object * int) option =
  let res = common_constrained_parse cons str base offset in
  match res with
    | Not_found _ -> None
    | Found x -> Some x
      
let constrained_parse cons str base offset : (Asn1.asn1_object * int) =
  let res = common_constrained_parse cons str base offset in
  match res with
    | Not_found err -> failwith err
    | Found x -> x
      
      
let rec parse_sequenceof cons n str base offset len =
  let substring = String.sub str offset len in
  let new_base = base + offset in
  
  let rec parse_aux offset =
    if offset = len
    then []
    else 
      let (next, new_offset) = constrained_parse cons substring new_base offset in
      next::(parse_aux new_offset)
  in
  let res = parse_aux 0 in
  let res_len = List.length res in
  match n with
    | AlwaysOK -> Asn1.Constructed res
    | Exactly num ->
      if num = res_len
      then Asn1.Constructed res
      else failwith ("The sequence should contain " ^ (string_of_int num) ^
			" elements, not " ^ (string_of_int (List.length res)) ^
			" at offset " ^ (string_of_int (base + offset)))
    | AtLeast num ->
      if num <= res_len
      then Asn1.Constructed res
      else failwith ("The sequence should contain at least " ^ (string_of_int num) ^
			" elements, not " ^ (string_of_int (List.length res)) ^
			" at offset " ^ (string_of_int (base + offset)))
    | AtMost num ->
      if num >= res_len
      then Asn1.Constructed res
      else failwith ("The sequence should contain at most " ^ (string_of_int num) ^
			" elements, not " ^ (string_of_int (List.length res)) ^
			" at offset " ^ (string_of_int (base + offset)))
    | Between (n1, n2) ->
      if n1 <= res_len && res_len <= n2
      then Asn1.Constructed res
      else failwith ("The sequence should contain between " ^ (string_of_int n1) ^
			" and " ^ (string_of_int n2) ^
			" elements, not " ^ (string_of_int (List.length res)) ^
			" at offset " ^ (string_of_int (base + offset)))
	
let rec parse_constrained_sequence (conss : (asn1_constraint * bool) list) str base offset len =
  let substring = String.sub str offset len in
  let new_base = base + offset in
  
  let rec parse_aux offset conss =
    match conss with
      | [] when offset < len ->
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
  Asn1.Constructed (parse_aux 0 conss)
    
    
let bool_cons = Simple_cons (Asn1.C_Universal, false, 1, Asn1.der_to_boolean)
let int_cons = Simple_cons (Asn1.C_Universal, false, 2, Asn1.der_to_int)
let bitstring_cons = Simple_cons (Asn1.C_Universal, false, 3, Asn1.der_to_bitstring)
let octetstring_cons = Simple_cons (Asn1.C_Universal, false, 4, Asn1.der_to_octetstring)
let oid_cons = Simple_cons (Asn1.C_Universal, false, 6, Asn1.der_to_oid)
let seqOf_cons cons n = Simple_cons (Asn1.C_Universal, true, 16, parse_sequenceof cons n)
let setOf_cons cons n = Simple_cons (Asn1.C_Universal, true, 17, parse_sequenceof cons n)
let custom_seq_cons c t conss = Simple_cons (c, true, t, parse_constrained_sequence conss)
  
let pkcs1_RSA_private_key = seqOf_cons int_cons (Exactly 9)
let pkcs1_RSA_public_key = seqOf_cons int_cons (Exactly 2)
  
  
let x509_version_cons = Simple_cons (Asn1.C_ContextSpecific, true, 0, parse_sequenceof int_cons (Exactly 1))
let x509_algoId_cons = custom_seq_cons Asn1.C_Universal 16 [(oid_cons, true); (Anything, false)]
let x509_atv_cons = custom_seq_cons Asn1.C_Universal 16 [(oid_cons, true); (Anything, true)]
let x509_rdn_cons = setOf_cons x509_atv_cons (AtLeast 1)
let x509_dn_cons = seqOf_cons x509_rdn_cons AlwaysOK
  
let x509_time_cons =
  let aux c isC t =
    if c = Asn1.C_Universal && not isC && (t = 23 || t = 24)
    then Some (Asn1.der_to_octetstring)
    else None
  in Complex_cons aux
  
let x509_validity_cons = seqOf_cons x509_time_cons (Exactly 2)
  
let x509_subject_pubkey_cons = custom_seq_cons Asn1.C_Universal 16
  [(x509_algoId_cons, true);
   (bitstring_cons, true)]
  
let x509_extension_cons = custom_seq_cons Asn1.C_Universal 16
  [(oid_cons, true);
   (bool_cons, false);
   (octetstring_cons, true)]
  
let x509_extensions_cons =
  Simple_cons (Asn1.C_ContextSpecific, true, 3,
	       parse_sequenceof (seqOf_cons x509_extension_cons AlwaysOK) (Exactly 1))
    
let x509_tbsCertificate_cons = custom_seq_cons Asn1.C_Universal 16
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
  
let x509_certificate_cons = custom_seq_cons Asn1.C_Universal 16
  [(x509_tbsCertificate_cons, true);
   (x509_algoId_cons, true);
   (bitstring_cons, true)]
  
let extract_tbs cert =
  match Asn1.decapsulate cert with
    | (Asn1.C_Universal, 16, Asn1.Constructed tbs)::
	(Asn1.C_Universal, 16, Asn1.Constructed _)::
	(Asn1.C_Universal, 3, Asn1.BitString _)::[]
      -> tbs
    | _ -> failwith "Invalid certificate"
      
let extract_dns tbs =
  match tbs with
    | (Asn1.C_ContextSpecific, 0, Asn1.Constructed _)::
	(Asn1.C_Universal, 2, Asn1.Integer _)::
	(Asn1.C_Universal, 16, Asn1.Constructed _)::
	(Asn1.C_Universal, 16, Asn1.Constructed i)::
	(Asn1.C_Universal, 16, Asn1.Constructed _)::
	(Asn1.C_Universal, 16, Asn1.Constructed s)::
	(Asn1.C_Universal, 16, Asn1.Constructed _)::r
      -> i, s
    | _ -> failwith "Invalid certificate"

(*let exts = List.hd (List.rev (tbs));;
let ext_list = Asn1.decapsulate (List.hd (Asn1.decapsulate exts))
let oid_of_ext = function
  | (Asn1.C_Universal, 16, Asn1.Constructed ((Asn1.C_Universal, 6, Asn1.OId l)::_)) -> l;;
List.map oid_of_ext ext_list;;
*)
