# configurable section
TARGETS =
MLLIBS = parsifal_formats
LIBNAME = parsifal_formats

parsifal_formats_SRCS := guid.ml pkcs7.ml pe.ml tar.ml png.ml dvi.ml uefi_fv.ml

# comment this line if not using camlp4
USE_CAMLP4 = yes

CC = gcc

# use the following lines to guess .cmxa files from libs names.
# remember, libs are always lowercase
OCAML_LIBS = unix lwt lwt.unix str cryptokit parsifal_syntax parsifal_core parsifal_net parsifal_ssl

# use the following variables to add extra flags (not guessed by ocamlfind)
EXTRA_OCAMLOPT_CC_FLAGS = -package parsifal_syntax
EXTRA_OCAMLOPT_LD_FLAGS = -I build mylzma.cmxa
EXTRA_OCAMLC_CC_FLAGS = -package parsifal_syntax
# XXX we add the .cma here to force it appear *before* uefi_fv (see end of this file)
EXTRA_OCAMLC_LD_FLAGS = build/mylzma.cma
EXTRA_CMXA_LD_FLAGS = build/lzma.cmx

BUILD_DIR = build

include ../Makefile.ocaml

build/unlzma.o: unlzma.c unlzma.h
	$(CC) -o $@ -c -g -fPIC $<

build/lzma_stubs.o: lzma_stubs.c
	$(OCAMLC) -o $@ -c -g $^ && mv $(@F) $@

build/libmylzma.a: build/lzma_stubs.o build/unlzma.o build/lzma.cmx
	ocamlmklib -o mylzma -Lbuild/ $^ && \
		mv libmylzma.a dllmylzma.so mylzma.a mylzma.cmxa build/

build/dllmylzma.so: build/libmylzma.a
build/mylzma.a: build/libmylzma.a
build/mylzma.cmxa: build/libmylzma.a

build/mylzma.cma: build/lzma.cmo build/dllmylzma.so
	$(OCAMLC) -a -o $@ $< -dllib -lmylzma -cclib -lmylzma -ccopt -Lbuild/ -I build/

# extra dependencies
build/lzma.cmo: build/lzma.cmi
build/lzma.cmx: build/lzma.cmi

# XXX problem: the .cma file here is added *after* uefi_fv
build/parsifal_formats.cma: build/mylzma.cma
# XXX problem: the .cmx file here is added *after* uefi_fv
build/parsifal_formats.cmxa:
