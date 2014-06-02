/* File generated from krb5.idl */

#include <stddef.h>
#include <string.h>
#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>
#include <caml/fail.h>
#include <caml/callback.h>
#ifdef Custom_tag
#include <caml/custom.h>
#include <caml/bigarray.h>
#endif
#include <caml/camlidlruntime.h>


#include "krb5.h"

void camlidl_ml2c_krb5_struct__mykrb5_keyblock(value _v1, struct _mykrb5_keyblock * _c2, camlidl_ctx _ctx)
{
  value _v3;
  value _v4;
  value _v5;
  mlsize_t _c6;
  mlsize_t _c7;
  value _v8;
  _v3 = Field(_v1, 0);
  (*_c2).magic = Int_val(_v3);
  _v4 = Field(_v1, 1);
  (*_c2).enctype = Int_val(_v4);
  _v5 = Field(_v1, 2);
  _c6 = Wosize_val(_v5);
  (*_c2).contents = camlidl_malloc(_c6 * sizeof(char ), _ctx);
  for (_c7 = 0; _c7 < _c6; _c7++) {
    _v8 = Field(_v5, _c7);
    (*_c2).contents[_c7] = Int_val(_v8);
  }
  (*_c2).length = _c6;
}

value camlidl_c2ml_krb5_struct__mykrb5_keyblock(struct _mykrb5_keyblock * _c1, camlidl_ctx _ctx)
{
  value _v2;
  value _v3[3];
  mlsize_t _c4;
  value _v5;
  _v3[0] = _v3[1] = _v3[2] = 0;
  Begin_roots_block(_v3, 3)
    _v3[0] = Val_int((*_c1).magic);
    _v3[1] = Val_int((*_c1).enctype);
    _v3[2] = camlidl_alloc((*_c1).length, 0);
    for (_c4 = 0; _c4 < (*_c1).length; _c4++) {
      _v5 = Val_int((unsigned char)((*_c1).contents[_c4]));
      modify(&Field(_v3[2], _c4), _v5);
    }
    _v2 = camlidl_alloc_small(3, 0);
    Field(_v2, 0) = _v3[0];
    Field(_v2, 1) = _v3[1];
    Field(_v2, 2) = _v3[2];
  End_roots()
  return _v2;
}

void camlidl_ml2c_krb5_mykrb5_keyblock(value _v1, mykrb5_keyblock * _c2, camlidl_ctx _ctx)
{
  camlidl_ml2c_krb5_struct__mykrb5_keyblock(_v1, &(*_c2), _ctx);
}

value camlidl_c2ml_krb5_mykrb5_keyblock(mykrb5_keyblock * _c2, camlidl_ctx _ctx)
{
value _v1;
  _v1 = camlidl_c2ml_krb5_struct__mykrb5_keyblock(&(*_c2), _ctx);
  return _v1;
}

void camlidl_ml2c_krb5_struct__mykrb5_data(value _v1, struct _mykrb5_data * _c2, camlidl_ctx _ctx)
{
  value _v3;
  value _v4;
  mlsize_t _c5;
  mlsize_t _c6;
  value _v7;
  _v3 = Field(_v1, 0);
  (*_c2).magic = Int_val(_v3);
  _v4 = Field(_v1, 1);
  _c5 = Wosize_val(_v4);
  (*_c2).data = camlidl_malloc(_c5 * sizeof(char ), _ctx);
  for (_c6 = 0; _c6 < _c5; _c6++) {
    _v7 = Field(_v4, _c6);
    (*_c2).data[_c6] = Int_val(_v7);
  }
  (*_c2).length = _c5;
}

value camlidl_c2ml_krb5_struct__mykrb5_data(struct _mykrb5_data * _c1, camlidl_ctx _ctx)
{
  value _v2;
  value _v3[2];
  mlsize_t _c4;
  value _v5;
  _v3[0] = _v3[1] = 0;
  Begin_roots_block(_v3, 2)
    _v3[0] = Val_int((*_c1).magic);
    _v3[1] = camlidl_alloc((*_c1).length, 0);
    for (_c4 = 0; _c4 < (*_c1).length; _c4++) {
      _v5 = Val_int((unsigned char)((*_c1).data[_c4]));
      modify(&Field(_v3[1], _c4), _v5);
    }
    _v2 = camlidl_alloc_small(2, 0);
    Field(_v2, 0) = _v3[0];
    Field(_v2, 1) = _v3[1];
  End_roots()
  return _v2;
}

void camlidl_ml2c_krb5_mykrb5_data(value _v1, mykrb5_data * _c2, camlidl_ctx _ctx)
{
  camlidl_ml2c_krb5_struct__mykrb5_data(_v1, &(*_c2), _ctx);
}

value camlidl_c2ml_krb5_mykrb5_data(mykrb5_data * _c2, camlidl_ctx _ctx)
{
value _v1;
  _v1 = camlidl_c2ml_krb5_struct__mykrb5_data(&(*_c2), _ctx);
  return _v1;
}

void camlidl_ml2c_krb5_struct__mykrb5_enc_data(value _v1, struct _mykrb5_enc_data * _c2, camlidl_ctx _ctx)
{
  value _v3;
  value _v4;
  value _v5;
  value _v6;
  _v3 = Field(_v1, 0);
  (*_c2).magic = Int_val(_v3);
  _v4 = Field(_v1, 1);
  (*_c2).enctype = Int_val(_v4);
  _v5 = Field(_v1, 2);
  (*_c2).kvno = Int_val(_v5);
  _v6 = Field(_v1, 3);
  camlidl_ml2c_krb5_mykrb5_data(_v6, &(*_c2).ciphertext, _ctx);
}

value camlidl_c2ml_krb5_struct__mykrb5_enc_data(struct _mykrb5_enc_data * _c1, camlidl_ctx _ctx)
{
  value _v2;
  value _v3[4];
  _v3[0] = _v3[1] = _v3[2] = _v3[3] = 0;
  Begin_roots_block(_v3, 4)
    _v3[0] = Val_int((*_c1).magic);
    _v3[1] = Val_int((*_c1).enctype);
    _v3[2] = Val_int((*_c1).kvno);
    _v3[3] = camlidl_c2ml_krb5_mykrb5_data(&(*_c1).ciphertext, _ctx);
    _v2 = camlidl_alloc_small(4, 0);
    Field(_v2, 0) = _v3[0];
    Field(_v2, 1) = _v3[1];
    Field(_v2, 2) = _v3[2];
    Field(_v2, 3) = _v3[3];
  End_roots()
  return _v2;
}

void camlidl_ml2c_krb5_mykrb5_enc_data(value _v1, mykrb5_enc_data * _c2, camlidl_ctx _ctx)
{
  camlidl_ml2c_krb5_struct__mykrb5_enc_data(_v1, &(*_c2), _ctx);
}

value camlidl_c2ml_krb5_mykrb5_enc_data(mykrb5_enc_data * _c2, camlidl_ctx _ctx)
{
value _v1;
  _v1 = camlidl_c2ml_krb5_struct__mykrb5_enc_data(&(*_c2), _ctx);
  return _v1;
}

value camlidl_krb5_ML_krb5_c_decrypt(
	value _v_key,
	value _v_usage,
	value _v_enc)
{
  mykrb5_keyblock key; /*in*/
  int usage; /*in*/
  mykrb5_enc_data enc; /*in*/
  mykrb5_data *decrypted; /*out*/
  int _res;
  struct camlidl_ctx_struct _ctxs = { CAMLIDL_TRANSIENT, NULL };
  camlidl_ctx _ctx = &_ctxs;
  mykrb5_data _c1;
  value _vresult;
  value _vres[2] = { 0, 0, };

  camlidl_ml2c_krb5_mykrb5_keyblock(_v_key, &key, _ctx);
  usage = Int_val(_v_usage);
  camlidl_ml2c_krb5_mykrb5_enc_data(_v_enc, &enc, _ctx);
  decrypted = &_c1;
  _res = ML_krb5_c_decrypt(key, usage, enc, decrypted);
  Begin_roots_block(_vres, 2)
    _vres[0] = Val_int(_res);
    _vres[1] = camlidl_c2ml_krb5_mykrb5_data(&*decrypted, _ctx);
    _vresult = camlidl_alloc_small(2, 0);
    Field(_vresult, 0) = _vres[0];
    Field(_vresult, 1) = _vres[1];
  End_roots()
  camlidl_free(_ctx);
  return _vresult;
}

