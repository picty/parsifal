open Common
open Types
open ParsingEngine
open X509
open X509Misc
open X509Validity
open X509PublicKey


let binary = ref false
let files = ref []

let options = [
  ("-DER", Arg.Set binary, "Inputs are DER files");
  ("-PEM", Arg.Clear binary, "Inputs are PEM files");
];;

let add_input s = files := s::(!files) in
Arg.parse options add_input "x509Check [options]";;


let read_content in_ch =
  let res = ref "" in
  let buf = String.make 4096 '\x00' in
  let rec read_bytes () =
    let n_bytes = input in_ch buf 0 4096 in
    if n_bytes = 0
    then !res
    else begin
      res := !res ^ (String.sub buf 0 n_bytes);
      read_bytes ()
    end
  in read_bytes()


let binary_contents =
  let open_files = match !files with
    | [] -> ["(stdin)", stdin]
    | _ -> List.map (fun s -> s, open_in s) !files
  in
  let extract_binary_content (n, f) =
    let content = read_content f in
    if !binary then n, content else n, (Base64.from_base64 None content)
  in
  List.map extract_binary_content open_files


type check_result = OK | Bof | KO

let string_of_check_result = function
  | OK -> "OK"
  | Bof -> "Bof"
  | KO -> "KO"

let int_of_check_result = function
  | OK -> 0
  | Bof -> 1
  | KO -> 2

let worst_res r1 r2 = if (int_of_check_result r2) > (int_of_check_result r1) then r1 else r2


(*type check_type =
  | Single of string * (certificate -> string * check_result)
  | Multiple of string * (certificate -> (string * check_result) list)*)


(* Version should be 3 *)
let check_version cert =
  match cert.tbs.version with
    | None -> "undefined", KO
    | Some v -> (string_of_int v), (if v >= 3 then OK else KO)


(* Serial should be 20 chars long at most *)
let check_serial cert =
  let n = String.length (cert.tbs.serial) in
  (Common.hexdump_with_separators ':' cert.tbs.serial) ^ " (length=" ^ (string_of_int n) ^ ")",
  if n > 20 then KO else OK


(* The signature algorithm should be the same in the TBS and in the
   Signature *)
let check_sigalgo1 cert =
  "", if cert.cert_sig_algo = cert.tbs.sig_algo then OK else KO

(* We expect robust signature algorithm *)
let check_sigalgo2 cert =
  let sa = Asn1.string_of_oid (cert.cert_sig_algo.oo_id) in
  match sa with
    | "sha256WithRSAEncryption" -> sa, OK
    | "sha1WithRSAEncryption" -> sa, Bof
    | _ -> sa, KO


(* Sanity checks on the dates *)
let check_validity cert =
  let not_before = _string_of_datetime cert.tbs.validity.not_before
  and not_after = _string_of_datetime cert.tbs.validity.not_after in
  if not_before < not_after
  then "notBefore < notAfter", OK
  else "notBefore >= notAfter", KO

let check_datetime dt =
  let tm = tm_of_datetime dt in
  let _, normalized_tm = Unix.mktime tm in
  let normalized_dt = datetime_of_tm normalized_tm in
  if _string_of_datetime normalized_dt = _string_of_datetime dt
  then (_string_of_datetime dt, OK)
  else ((_string_of_datetime dt) ^ " <> [normalized] " ^ (_string_of_datetime normalized_dt), KO)

  
(* Is the certificate valid *)
let check_validity_now cert =
  let not_before = _string_of_datetime cert.tbs.validity.not_before
  and not_after = _string_of_datetime cert.tbs.validity.not_after
  and now = _string_of_datetime (datetime_of_tm (Unix.gmtime (Unix.time ())))
  in
  if (not_before <= now) && (now <= not_after)
  then "", OK
  else not_before ^ " ? " ^ now ^ " ? " ^ not_after ^ "no", KO

(* Check how long the certificate is valid *)	
let check_validity_in_month cert =
  let not_before, _ = Unix.mktime (tm_of_datetime cert.tbs.validity.not_before)
  and not_after, _ = Unix.mktime (tm_of_datetime cert.tbs.validity.not_after) in
  let nSeconds = not_after -. not_before in
  let nMonths = int_of_float (ceil (nSeconds /. (3600. *. 24. *. 365.25 /. 12.))) in
  (* TODO: Work on that... *)
  (string_of_int nMonths) ^ " months", OK


(* We expect public key to be known *)
let check_public_key cert =
  let pki = cert.tbs.pk_info in
  let pka = Asn1.string_of_oid (pki.pk_algo.oo_id) in
  match pka with
    (* TODO: Factor this? *)
    | "rsaEncryption" ->
      let n = eval_as_string (hash_find (eval_as_dict pki.public_key) "n") in
(*      let e = eval_as_string (hash_find (eval_as_dict pki.public_key) "e") in *)
      let n_len = String.length n in
      let n_reallen = if n.[0] = '\x00' then n_len - 1 else n_len in
      "RSA " ^ (string_of_int (n_reallen * 8)), OK
    | _ -> pka, KO



let process_check cert current_res (name, f) =
  Printf.printf "  %s" name;
  let str, res = f cert in
  if str <> ""
  then Printf.printf ": %s (%s)\n" str (string_of_check_result (res))
  else Printf.printf ": %s\n" (string_of_check_result (res));
  max current_res res


let common_checks = [
  "Version", check_version;
  "Serial", check_serial;
  "Matching signature algorithms", check_sigalgo1;
  "Signature algorithm robustness", check_sigalgo2;
  "Validity sanity checks", check_validity;
  "                      ", (fun cert -> check_datetime cert.tbs.validity.not_before);
  "                      ", (fun cert -> check_datetime cert.tbs.validity.not_after);
  "Current validity", check_validity_now;
  "How long the certificate is valid", check_validity_in_month;
  "Public key", check_public_key;
]


let print_asn1_error sev (err, pstate_str) =
  Printf.printf "  [ASN1 error (%s)] %s inside %s\n" (string_of_severity sev) (strerror err) pstate_str

let print_asn1_errors tab =
  for i=s_fatal downto s_ok do
    List.iter (print_asn1_error i) (List.rev tab.(i))
  done

let check_input (name, content) =
  Printf.printf "%s:\n" name;
  let error_table = Array.create (s_fatal + 1) [] in
  let ehf = recording_error_handling_function error_table in
  let pstate = _pstate_of_string ehf (Some name) content in
  try
    let cert = X509.parse pstate in
    print_asn1_errors error_table;
    let res = List.fold_left (process_check cert) OK common_checks in
    Printf.printf "Result: %s\n\n" (string_of_check_result res)
  with
    | OutOfBounds s -> output_string stderr ("Out of bounds in " ^ s ^ ")")
    | ParsingError (err, sev, pstate) -> output_string stderr (string_of_parsing_error "Fatal" err sev pstate);;


let _ =
  List.iter check_input binary_contents

