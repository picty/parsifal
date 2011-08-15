(* 
   ocamlc nums.cma asn1.ml
   ocamlc nums.cma asn1.cmo validasn1.ml
   ocamlc nums.cma asn1.cmo validasn1.cmo
   rlwrap ocaml nums.cma asn1.cmo validasn1.cmo test.ml
*)

open Asn1;;
open Validasn1;;

let f = open_in "AC_RACINE_NEW.der";;
let s = String.create 1609;;
really_input f s 0 1609;;
let c = Asn1.parse s 0 0;;

