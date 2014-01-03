#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/custom.h>
#include <caml/alloc.h>
#include <caml/fail.h>
#include <caml/callback.h>

#include "unlzma.h"

static void error(char *s)
{
	fprintf(stderr, "ERROR %s\n", s);
	exit(1);
}

CAMLprim value caml_lzma_getsize(value buf, value buf_size)
{
	unsigned char *c_src = (unsigned char *)String_val(buf);
	long c_src_size = caml_string_length(buf);
	int ret;
	int out_len;

	ret = unlzma(c_src, c_src_size, NULL, NULL, NULL, &out_len, NULL, error);
	if (ret == 0)
		return Val_long(out_len);
	return Val_long(-1);
}

CAMLprim value caml_lzma_decode(value src, value src_size, value dst, value dst_size)
{
	unsigned char *c_src = (unsigned char *)String_val(src);
	long c_src_size = caml_string_length(src);
	unsigned char *c_dst = (unsigned char *)String_val(dst);
	long c_dst_size = Long_val(dst_size);

	//printf("uncompressing (c_src_size: %ld -> c_dst_size: %ld)\n", c_src_size, c_dst_size);
	unlzma(c_src, c_src_size, NULL, NULL, c_dst, (int*)&c_dst_size, NULL, error);

	return Val_long(0);
}

