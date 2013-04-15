alias ustar_magic = magic["ustar"]
alias tar_file = list of tar_entry

struct atv_content = {
  attributeType : der_oid;
  attributeValue : der_object
}
asn1_alias atv
asn1_alias rdn = set_of atv
asn1_alias distinguishedName = seq_of rdn
