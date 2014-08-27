# configurable section
TARGETS = test_tar test_pe test_dvi test_uefi_fv

test_tar_SRCS := test_tar.ml
test_pe_SRCS := test_pe.ml
test_dvi_SRCS := test_dvi.ml
test_uefi_fv_SRCS := test_uefi_fv.ml

# comment this line if not using camlp4
USE_CAMLP4 = yes

CC = gcc

# use the following lines to guess .cmxa files from libs names.
# remember, libs are always lowercase
OCAML_LIBS = unix lwt lwt.unix str calendar cryptokit \
	parsifal_syntax parsifal_core parsifal_lwt \
	parsifal_crypto parsifal_formats

# use the following variables to add extra flags (not guessed by ocamlfind)
EXTRA_OCAMLOPT_CC_FLAGS = -package parsifal_syntax
EXTRA_OCAMLOPT_LD_FLAGS = -cclib -lmylzma -cclib -lmytiano -ccopt -Lbuild/
EXTRA_OCAMLC_CC_FLAGS = -package parsifal_syntax
EXTRA_OCAMLC_LD_FLAGS =

BUILD_DIR = build



include ../../Makefile.ocaml


check: all
