open Asn1PTypes

struct rsa_private_key_content = {
  version : der_smallint;
  modulus : der_integer;
  publicExponent : der_integer;
  privateExponent : der_integer;
  prime1 : der_integer;
  prime2 : der_integer;
  exponent1 : der_integer;
  exponent2 : der_integer;
  coefficient : der_integer
}
asn1_alias rsa_private_key


struct rsa_public_key_content = {
  p_modulus : der_integer;
  p_publicExponent : der_integer
}
asn1_alias rsa_public_key
