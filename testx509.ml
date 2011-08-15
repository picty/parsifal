(* 
   ocamlc nums.cma asn1.ml
   ocamlc nums.cma asn1.cmo validasn1.ml
   ocamlc nums.cma asn1.cmo validasn1.cmo x509.ml
   rlwrap ocaml nums.cma asn1.cmo validasn1.cmo x509.cmo test-x509.ml
*)

open Asn1;;
open X509;;

let f = open_in "AC_RACINE_NEW.der";;
let s = String.create 1609;;
really_input f s 0 1609;;
let c = string_to_certificate s;;

