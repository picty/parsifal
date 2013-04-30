open Asn1PTypes

asn1_struct dh_params = {
  dh_p : der_integer;
  dh_g : der_integer;
  dh_order : der_integer
}

alias dh_public_key = der_integer
