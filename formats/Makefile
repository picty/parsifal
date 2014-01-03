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
EXTRA_OCAMLOPT_LD_FLAGS = -I build lzma.cmxa
EXTRA_OCAMLC_CC_FLAGS = -package parsifal_syntax
EXTRA_OCAMLC_LD_FLAGS = build/lzma.cmo build/liblzma_stubs.o build/unlzma.o
EXTRA_CMXA_LD_FLAGS = build/liblzma_stubs.a build/lzma.cmx

BUILD_DIR = build

include ../Makefile.ocaml

build/unlzma.o: unlzma.c unlzma.h
	$(CC) -o $@ -c -g -fPIC $<

build/lzma_stubs.o: lzma_stubs.c
	$(OCAMLC) -o $@ -c -g $^ && mv $(@F) $@

build/liblzma_stubs.a: build/lzma_stubs.o build/unlzma.o
	ocamlmklib -oc lzma_stubs $^ && mv liblzma_stubs.a dlllzma_stubs.so build/

#lzma.cmi: lzma.mli lzma.ml
#	ocamlc -g -c lzma.mli

#lzma.cmo: lzma.ml lzma.cmi
#	ocamlc -g -c lzma.ml

#lzma.cmx: lzma.ml lzma.cmi
#	ocamlopt -g -c lzma.ml

build/lzma.cmo: build/lzma.cmi
build/lzma.cmx: build/lzma.cmi

build/lzma.cma: build/lzma.cmo build/liblzma_stubs.a
	$(OCAMLC) -g -a -o $@ -dllib -llzma_stubs $<

build/lzma.a: build/liblzma_stubs.a build/lzma.cmx
	ocamlmklib -o lzma -Lbuild/ -llzma_stubs $< && \
		mv lzma.a lzma.cmxa build/

build/lzma.cmxa: build/lzma.a

build/lzma.cmxs: build/lzma.cmxa
	$(OCAMLOPT) -g -shared -linkall -o $@ $<

build/parsifal_formats.cma: build/lzma.cmo
#build/parsifal_formats.cmxa: build/lzma.cmx build/liblzma_stubs.a
