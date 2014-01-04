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

#include "EfiTianoDecompress.h"

static void error(char *s)
{
	fprintf(stderr, "ERROR %s\n", s);
	exit(1);
}

CAMLprim value caml_tiano_getsize(value buf, value buf_size)
{
	unsigned char *c_src = (unsigned char *)String_val(buf);
	long c_src_size = caml_string_length(buf);
	//int ret;
	//int out_len;
	//UINT8* scratch;
	UINT32 scratchSize = 0;
	UINT32 decompressedSize = 0;
	EFI_TIANO_HEADER* header;

	header = (EFI_TIANO_HEADER*) c_src;
	if (header->CompSize + sizeof(EFI_TIANO_HEADER) != c_src_size)
		return Val_long(-1);

	if (ERR_SUCCESS != EfiTianoGetInfo(c_src, c_src_size, &decompressedSize, &scratchSize))
		return Val_long(-2);

	//scratch = malloc(scratchSize);
	//fprintf(stdout, "tiano_getsize: %ld\n", decompressedSize);

	return Val_long(decompressedSize);
}

CAMLprim value caml_tiano_decode(value src, value src_size, value dst, value dst_size)
{
	UINT8* scratch;
	UINT32 scratchSize = 0;
	UINT32 decompressedSize = 0;
	EFI_TIANO_HEADER* header;
	unsigned char *c_src = (unsigned char *)String_val(src);
	long c_src_size = caml_string_length(src);
	unsigned char *c_dst = (unsigned char *)String_val(dst);
	long c_dst_size = Long_val(dst_size);

	//printf("uncompressing (c_src_size: %ld -> c_dst_size: %ld)\n", c_src_size, c_dst_size);

	header = (EFI_TIANO_HEADER*) c_src;
	if (header->CompSize + sizeof(EFI_TIANO_HEADER) != c_src_size)
		return Val_long(-1);

	if (ERR_SUCCESS != EfiTianoGetInfo(c_src, c_src_size, &decompressedSize, &scratchSize))
		return Val_long(-2);

	if (c_dst_size < decompressedSize)
		return Val_long(-3);

	scratch = malloc(scratchSize);

	if (ERR_SUCCESS != TianoDecompress(c_src, c_src_size, c_dst, decompressedSize, scratch, scratchSize))
		return Val_long(-4);
	//untiano(c_src, c_src_size, NULL, NULL, c_dst, (int*)&c_dst_size, NULL, error);

	free(scratch);
	return Val_long(0);
}

