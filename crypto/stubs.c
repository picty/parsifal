#include <caml/memory.h>
#include <caml/mlvalues.h>
#include <caml/alloc.h>
#include "md5.h"
#include "sha1.h"

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
