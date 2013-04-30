# configurable section
TARGETS = test_basePTypes test_base64

test_basePTypes_SRCS := test_basePTypes.ml
test_base64_SRCS := test_base64.ml

# comment this line if not using camlp4
USE_CAMLP4 = yes

CC = gcc

# use the following lines to guess .cmxa files from libs names.
# remember, libs are always lowercase
OCAML_LIBS = unix lwt lwt.unix str cryptokit parsifal_syntax parsifal_core oUnit

# use the following variables to add extra flags (not guessed by ocamlfind)
EXTRA_OCAMLOPT_CC_FLAGS = -package parsifal_syntax
EXTRA_OCAMLOPT_LD_FLAGS =
EXTRA_OCAMLC_CC_FLAGS = -package parsifal_syntax
EXTRA_OCAMLC_LD_FLAGS =

BUILD_DIR = build



include ../../Makefile.ocaml


check:	test_basePTypes.byte test_basePTypes test_base64.byte test_base64
	./test_basePTypes.byte
	./test_basePTypes
	./test_base64.byte
	./test_base64
