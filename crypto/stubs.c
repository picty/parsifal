#include <caml/memory.h>
#include <caml/mlvalues.h>
#include <caml/alloc.h>
#include "md5.h"
#include "sha1.h"
#include <gmp.h>


value md5sum (value caml_s) {
  CAMLparam1 (caml_s);
  CAMLlocal1 (caml_res);

  caml_res = caml_alloc_string (16);
  unsigned char* res = (unsigned char*) String_val (caml_res);

  const unsigned char* s = (const unsigned char*) String_val (caml_s);
  size_t n = caml_string_length(caml_s);

  md5 (s, n, res);

  CAMLreturn (caml_res);
}
  
value sha1sum (value caml_s) {
  CAMLparam1 (caml_s);
  CAMLlocal1 (caml_res);

  caml_res = caml_alloc_string (20);
  unsigned char* res = (unsigned char*) String_val (caml_res);

  const unsigned char* s = (const unsigned char*) String_val (caml_s);
  size_t n = caml_string_length(caml_s);

  sha1 (s, n, res);

  CAMLreturn (caml_res);
}

value sha224_256sum (value caml_s, value caml_is224) {
  CAMLparam2 (caml_s, caml_is224);
  CAMLlocal1 (caml_res);

  int is224 = Bool_val (caml_is224);
  caml_res = caml_alloc_string (is224 ? 28 : 32);
  unsigned char* res = (unsigned char*) String_val (caml_res);

  const unsigned char* s = (const unsigned char*) String_val (caml_s);
  size_t n = caml_string_length(caml_s);

  sha2 (s, n, res, is224);

  CAMLreturn (caml_res);
}

value sha384_512sum (value caml_s, value caml_is384) {
  CAMLparam2 (caml_s, caml_is384);
  CAMLlocal1 (caml_res);

  int is384 = Bool_val (caml_is384);
  caml_res = caml_alloc_string (is384 ? 48 : 64);
  unsigned char* res = (unsigned char*) String_val (caml_res);

  const unsigned char* s = (const unsigned char*) String_val (caml_s);
  size_t n = caml_string_length(caml_s);

  sha4 (s, n, res, is384);

  CAMLreturn (caml_res);
}


const char* hexachar = "0123456789abcdef";
const char hexachar_rev[256] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0, 0,
				0,10,11,12,13,14,15, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0,10,11,12,13,14,15, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

static int mk_mpz (mpz_t* res, value caml_value) {
  const char* x_str = String_val (caml_value);
  size_t x_size = caml_string_length(caml_value);
  char* x_hexa = (char*) malloc (x_size * 2 + 1);
  size_t i;

  if (x_hexa == NULL) return 0;

  for (i = 0; i<x_size; i++) {
    x_hexa[2 * i] = hexachar[(x_str [i] >> 4) & 0xf];
    x_hexa[2 * i + 1] = hexachar[x_str [i] & 0xf];
  }
  x_hexa [2 * x_size] = 0;

  mpz_init_set_str (*res, x_hexa, 16);

  free (x_hexa);
  return (res != NULL);
}


value exp_mod (value caml_x, value caml_e, value caml_n) {
  CAMLparam3 (caml_x, caml_e, caml_n);
  CAMLlocal1 (caml_res);

  mpz_t x, e, n;
  int res = mk_mpz (&x, caml_x) && mk_mpz (&e, caml_e) && mk_mpz (&n, caml_n);

  if (res) {
    size_t n_len = (mpz_sizeinbase (n, 16) + 1) / 2;
    char* s;
    char* res;
    size_t i, s_len;

    mpz_powm (x, x, e, n);
    s = mpz_get_str (NULL, 16, x);
    s_len = strlen (s);

    mpz_clear (x); mpz_clear (e); mpz_clear (n);

    caml_res = caml_alloc_string (n_len);
    res = String_val (caml_res);
    for (i=0; i<n_len; i++)
      res[i] = 0;

    for (i=0; i<(s_len/2); i++)
      res[n_len-1-i] = (hexachar_rev[s[(s_len - 1) - 2 * i - 1]] << 4) | hexachar_rev[s[(s_len - 1) - 2 * i]];

    if (s_len % 2 != 0)
      res[n_len-1-(s_len/2)] = hexachar_rev[s[0]];

    free (s);
  } else {
    caml_res = caml_alloc_string (0);
  }

  CAMLreturn (caml_res);
}
