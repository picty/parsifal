# configurable section
TARGETS = test_random test_rsa_private_key test_ssl2 test_tls_record

test_random_SRCS := test_random.ml
test_rsa_private_key_SRCS := test_rsa_private_key.ml
test_ssl2_SRCS := test_ssl2.ml
test_tls_record_SRCS := test_tls_record.ml

# comment this line if not using camlp4
USE_CAMLP4 = yes

CC = gcc

# use the following lines to guess .cmxa files from libs names.
# remember, libs are always lowercase
OCAML_LIBS = unix lwt lwt.unix str cryptokit parsifal_syntax parsifal_core parsifal_net parsifal_ssl

# use the following variables to add extra flags (not guessed by ocamlfind)
EXTRA_OCAMLOPT_CC_FLAGS = -package parsifal_syntax
EXTRA_OCAMLOPT_LD_FLAGS =
EXTRA_OCAMLC_CC_FLAGS = -package parsifal_syntax
EXTRA_OCAMLC_LD_FLAGS =

BUILD_DIR = build



include ../../Makefile.ocaml


check: all
	./test_random
