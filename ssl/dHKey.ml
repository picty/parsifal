open Asn1PTypes

struct dh_params_content = {
  dh_p : der_integer;
  dh_g : der_integer;
  dh_order : der_integer
}
asn1_alias dh_params


alias dh_public_key = der_integer
