open Types
open Modules
open Printer
open ParsingEngine
open Asn1
open Asn1Constraints
open X509Misc


(* Signature *)

(* This param is declared here, but is accessible via the x509 module *)
let parse_signature = ref true

type signature = value
let empty_signature = V_Unit

type sig_parse_fun = int -> string -> value
let (signature_directory : (int list, sig_parse_fun) Hashtbl.t) = Hashtbl.create 10

let extract_signature algo (n, s) =
  try
    if !parse_signature then begin
      let extract_aux = Hashtbl.find signature_directory algo.oo_id in
      extract_aux n s
    end else V_BitString (n, s)
  with Not_found -> V_BitString (n, s)


let signature_constraint sigalgo : signature asn1_constraint =
  Simple_cons (C_Universal, false, 3, "Bit String",
	       fun pstate -> extract_signature sigalgo (raw_der_to_bitstring pstate))

let string_of_signature indent signature = PrinterLib._string_of_value indent true signature
