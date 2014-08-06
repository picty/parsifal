# configurable section
TARGETS = test_prf test_suites

test_prf_SRCS := test_prf.ml
test_suites_SRCS := test_suites.ml

# comment this line if not using camlp4
USE_CAMLP4 = yes

CC = gcc

# use the following lines to guess .cmxa files from libs names.
# remember, libs are always lowercase
OCAML_LIBS = unix lwt lwt.unix str cryptokit parsifal_syntax parsifal_core parsifal_lwt \
	parsifal_crypto parsifal_net parsifal_ssl oUnit

# use the following variables to add extra flags (not guessed by ocamlfind)
EXTRA_OCAMLOPT_CC_FLAGS = -package parsifal_syntax
EXTRA_OCAMLOPT_LD_FLAGS =
EXTRA_OCAMLC_CC_FLAGS = -package parsifal_syntax
EXTRA_OCAMLC_LD_FLAGS =

BUILD_DIR = build



include ../../Makefile.ocaml


check:	test_prf test_suites
	./test_prf
	./test_suites
