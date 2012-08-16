open Common
open Types
open ParsingEngine
open X509
open X509Validity
open X509PublicKey
open X509Extensions
open X509Misc
open X509DN


let mk_hash s =
  String.sub (hexdump (Crypto.sha1sum s)) 0 16

(* no =, no /, no : *)
let only_printable_and_no_special s =
  let n = String.length s in
  let res = String.create (n * 4) in
  let rec aux src dst =
    if src == n
    then String.sub res 0 dst
    else begin
      let c = s.[src] in
      let ord = int_of_char c in
      if ord >= 32 && ord < 128 && c <> ':' && c <> '/' && c <> '='
      then begin
	res.[dst] <- c;
	aux (src + 1) (dst + 1)
      end else begin
	res.[dst] <- '\\';
	res.[dst+1] <- 'x';
	res.[dst+2] <- hexa_char.[ord / 16];
	res.[dst+3] <- hexa_char.[ord mod 16];
	aux (src + 1) (dst + 4)
      end
    end
  in aux 0 0

let my_short_display dn =
  let short_of_atv atv =
    let oid_str =
      try Hashtbl.find X509DN.initial_directory atv.oo_id
      with Not_found -> Asn1.string_of_oid atv.oo_id
    and content_str = match atv.oo_content with
      | None -> ""
      | Some o -> String.concat "," (fst (Asn1.string_of_content o.Asn1.a_content))
    in "/" ^ oid_str ^ "=" ^ (only_printable_and_no_special content_str)
  in String.concat "" (List.map short_of_atv (List.flatten dn))


let print_ev dn oid =
  Printf.printf "%s:%s\n" (mk_hash (my_short_display dn)) oid

let _ =
  try
    while true do
      let line = read_line () in
      try
	match string_split ':' line with
	  | [dn_pem;oid] ->
	    let pstate = pstate_of_string None (Base64.from_raw_base64 dn_pem) in
	    let dn = DNParser.parse pstate
	    in print_ev dn oid
	  | _ -> failwith "Shitty line"
      with
	| _ -> print_endline ("CertificateUnparsed:" ^ line)
    done
  with End_of_file -> ()
