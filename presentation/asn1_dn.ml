struct atv_content = {
  attributeType : der_oid;
  attributeValue : der_object
}
asn1_alias atv
asn1_alias rdn = set_of atv  (* min = 1 *)
asn1_alias distinguishedName = seq_of rdn
