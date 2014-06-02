/* File generated from krb5.idl */

#ifndef _CAMLIDL_KRB5_H
#define _CAMLIDL_KRB5_H

#ifdef __cplusplus
#define _CAMLIDL_EXTERN_C extern "C"
#else
#define _CAMLIDL_EXTERN_C extern
#endif

#ifdef _WIN32
#pragma pack(push,8) /* necessary for COM interfaces */
#endif

struct _mykrb5_keyblock {
  int magic;
  int enctype;
  int length;
  char *contents;
};

typedef struct _mykrb5_keyblock mykrb5_keyblock;

struct _mykrb5_data {
  int magic;
  unsigned int length;
  char *data;
};

typedef struct _mykrb5_data mykrb5_data;

struct _mykrb5_enc_data {
  int magic;
  int enctype;
  unsigned int kvno;
  mykrb5_data ciphertext;
};

typedef struct _mykrb5_enc_data mykrb5_enc_data;

_CAMLIDL_EXTERN_C int ML_krb5_c_decrypt(/*in*/ mykrb5_keyblock key, /*in*/ int usage, /*in*/ mykrb5_enc_data enc, /*out*/ mykrb5_data *decrypted);

#ifdef _WIN32
#pragma pack(pop)
#endif


#endif /* !_CAMLIDL_KRB5_H */
