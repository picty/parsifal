open Asn1PTypes

struct dsa_params_content = {
  dsa_p : der_integer;
  dsa_q : der_integer;
  dsa_g : der_integer
}
asn1_alias dsa_params


(* TODO: Add checks? *)
alias dsa_public_key = der_integer


struct dsa_signature_content = {
  dsa_r : der_integer;
  dsa_s : der_integer
}
asn1_alias dsa_signature

