(* File generated from krb5.idl *)

type _mykrb5_keyblock = {
  _mykrb5_keyblock_magic: int;
  _mykrb5_keyblock_enctype: int;
  _mykrb5_keyblock_contents: char array;
}
and mykrb5_keyblock = _mykrb5_keyblock
and _mykrb5_data = {
  _mykrb5_data_magic: int;
  _mykrb5_data_data: char array;
}
and mykrb5_data = _mykrb5_data
and _mykrb5_enc_data = {
  _mykrb5_enc_data_magic: int;
  _mykrb5_enc_data_enctype: int;
  _mykrb5_enc_data_kvno: int;
  _mykrb5_enc_data_ciphertext: mykrb5_data;
}
and mykrb5_enc_data = _mykrb5_enc_data

external mL_krb5_c_decrypt : mykrb5_keyblock -> int -> mykrb5_enc_data -> int * mykrb5_data
	= "camlidl_krb5_ML_krb5_c_decrypt"

