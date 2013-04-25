open Asn1PTypes

asn1_struct rsa_private_key = {
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


asn1_struct rsa_public_key = {
  p_modulus : der_integer;
  p_publicExponent : der_integer
}


alias rsa_signature = der_integer_content
