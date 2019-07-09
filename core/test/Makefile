# configurable section
TARGETS = test_parsifal test_getopt test_protobuf

test_parsifal_SRCS := test_parsifal.ml
test_getopt_SRCS := test_getopt.ml
test_protobuf_SRCS := test_protobuf.ml

# comment this line if not using camlp4
USE_CAMLP4 = yes

CC = gcc

# use the following lines to guess .cmxa files from libs names.
# remember, libs are always lowercase
OCAML_LIBS = unix str calendar parsifal_syntax parsifal_core

# use the following variables to add extra flags (not guessed by ocamlfind)
EXTRA_OCAMLOPT_CC_FLAGS = -package parsifal_syntax
EXTRA_OCAMLOPT_LD_FLAGS =
EXTRA_OCAMLC_CC_FLAGS = -package parsifal_syntax
EXTRA_OCAMLC_LD_FLAGS =

BUILD_DIR = build



include ../../Makefile.ocaml


check:	all
	./test_parsifal
