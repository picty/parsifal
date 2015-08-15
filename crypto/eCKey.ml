open Asn1PTypes

alias ec_params = der_object

alias ec_public_key = binstring

asn1_struct ecdsa_signature = {
  ecdsa_x : der_integer;
  ecdsa_y : der_integer
}
