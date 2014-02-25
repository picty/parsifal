open Asn1PTypes

asn1_struct dsa_params = {
  dsa_p : der_integer;
  dsa_q : der_integer;
  dsa_g : der_integer
}


(* TODO: Add checks? *)
alias dsa_public_key = der_integer


asn1_struct dsa_signature = {
  dsa_r : der_integer;
  dsa_s : der_integer
}

