open Parsifal
open PTypes
open Asn1PTypes
open Asn1Engine
open Padata

(* ContextSpecific optimization *)
type 'a cspe = 'a
let parse_cspe n parse_fun input = parse_asn1 (C_ContextSpecific, true, T_Unknown n) parse_fun input
let dump_cspe n dump_fun buf o = dump_asn1 (C_ContextSpecific, true, T_Unknown n) dump_fun buf o
let value_of_cspe = BasePTypes.value_of_container

asn1_struct encrypted_data =
{
  encryption_type :     cspe [0] of asn1 [(C_Universal, false, T_Integer)] of etype_type;
  optional kvno :       cspe [1] of der_smallint;
  cipher :              cspe [2] of der_octetstring
}
