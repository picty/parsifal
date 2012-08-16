(*

for i in $(cd ../../Campaigns; find -type d -name '[0-9]*'); do
  ./gather_data.sh ../../Campaigns . $i
done

gather_data:
#!/bin/sh

find "$1/$3" -name '*.dump' | while read i; do
  name=$(basename "$i")
  destdir="$2/$3"
  dest="$destdir/${name/.dump/.cs}"
  mkdir -p "$destdir"
  echo "$i" '->' "$dest"
  ~/dev/FAceSL/extract_ciphersuites.native < "$i" > "$dest" 
  awk '{ print $2 "\t" $3 }' "$dest" | grep -v '!' | sort | uniq -c | sort -nr > "$dest.stats"
done

*)


open Common
open Types
open ParsingEngine
open BinaryRecord
open AnswerDump
open Tls
open TlsCommon
open TlsRecord
open TlsHandshake


let get_name answer =
  let name = eval_as_string (answer --> "name") in
  if String.length name = 0
  then Common.string_of_ip4 (eval_as_ipv4 (answer --> "ip"))
  else name


let extract_ciphersuite msg =
  let (hs_t, hs_msg) = HandshakeModule.pop_object msg.content in
  if msg.content_type = 22 && hs_t = 2
  then (Some (eval_as_int ((eval_as_dict hs_msg) --> "cipher_suite")))
  else None

let keep_somes = function
  | None -> false
  | Some _ -> true


let _ =
  let pstate = pstate_of_channel "(stdin)" stdin in

  TlsHandshake.parse_certificates := false;
  tolerance := s_specfatallyviolated;
  minDisplay := s_specfatallyviolated;
  
  try
    while not (eos pstate) do
      let answer = BinaryRecord.parse AnswerDump.description pstate in
      let name = get_name answer in
      let tls_ciphersuites = 
	try
	  let tls_pstate = pstate_of_string (Some name) (eval_as_string (answer --> "content")) in
	  let tls_msgs = List.map TlsRecord.RecordModule.pop_object (Tls.TlsLib._parse tls_pstate) in
	  List.filter keep_somes (List.map extract_ciphersuite tls_msgs)
	with _ -> []
      in
      match tls_ciphersuites with
	| [] -> Printf.printf "%s\t! no server hello\n" name;
	| [Some cs] -> Printf.printf "%s\t(%4.4x) %s\n" name cs (cipher_suite_string_of_int cs);
	| _ -> Printf.printf "%s\t! multiple server hello?\n" name;
    done
  with
    | OutOfBounds s ->
      output_string stderr ("Out of bounds (" ^ s ^ ")\n")
    | ParsingError (err, sev, pstate) ->
      output_string stderr ((string_of_parsing_error "Parsing error" err sev pstate) ^ "\n");;
