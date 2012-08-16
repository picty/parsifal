open Common
open Types
open ParsingEngine
open BinaryRecord
open AnswerDump
open X509
open X509PublicKey
open Tls
open TlsCommon
open TlsRecord
open TlsHandshake


let get_name answer =
  let name = eval_as_string (answer --> "name") in
  if String.length name = 0
  then Common.string_of_ip4 (eval_as_ipv4 (answer --> "ip"))
  else name


let modulus_of_cert accu cert_val =
  try
    let cert = X509Module.pop_object cert_val in
    let pk = eval_as_dict (cert.tbs.pk_info.public_key) in
    if eval_as_string (pk --> "type") = "RSA"
    then (eval_as_string (pk --> "n") , eval_as_string (pk --> "e"))::accu
    else accu
  with _ -> accu
      

let extract_moduli msg =
  let (hs_t, hs_msg) = HandshakeModule.pop_object msg.content in
  if msg.content_type = 22 && hs_t = 11
  then List.fold_left modulus_of_cert [] (eval_as_list hs_msg)
  else []


let iteri f l =
  let rec iteri_aux i = function
    | [] -> ()
    | x::r -> f i x; iteri_aux (i+1) r
  in iteri_aux 0 l


let _ =
  let pstate = pstate_of_channel "(stdin)" stdin in

  X509Extensions.parse_extensions := false;
  TlsHandshake.parse_certificates := true;
  parse_public_key := true;

  tolerance := s_specfatallyviolated;
  minDisplay := s_specfatallyviolated;
  
  try
    while not (eos pstate) do
      let answer = BinaryRecord.parse AnswerDump.description pstate in
      let name = get_name answer in
      let tls_moduli = 
	try
	  let tls_pstate = pstate_of_string (Some name) (eval_as_string (answer --> "content")) in
	  let tls_msgs = List.map TlsRecord.RecordModule.pop_object (Tls.TlsLib._parse tls_pstate) in
	  List.flatten (List.map extract_moduli tls_msgs)
	with _ -> []
      in
      match tls_moduli with
	| [] -> Printf.printf "%s\t! no certificates\n" name;
	| _ -> iteri (fun i -> fun (n, e) -> Printf.printf "%s-%d %s:%s\n" name i (hexdump n) (hexdump e)) tls_moduli
    done
  with
    | OutOfBounds s ->
      output_string stderr ("Out of bounds (" ^ s ^ ")\n")
    | ParsingError (err, sev, pstate) ->
      output_string stderr ((string_of_parsing_error "Parsing error" err sev pstate) ^ "\n");;
