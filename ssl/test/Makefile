# configurable section
TARGETS = test_ssl2 test_tls_client test_tls_server

test_ssl2_SRCS := test_ssl2.ml
test_tls_client_SRCS := test_tls_client.ml
test_tls_server_SRCS := test_tls_server.ml

# comment this line if not using camlp4
USE_CAMLP4 = yes

CC = gcc

# use the following lines to guess .cmxa files from libs names.
# remember, libs are always lowercase
OCAML_LIBS = unix lwt lwt.unix str calendar cryptokit \
	parsifal_syntax parsifal_core parsifal_lwt \
	parsifal_crypto parsifal_net parsifal_ssl

# use the following variables to add extra flags (not guessed by ocamlfind)
EXTRA_OCAMLOPT_CC_FLAGS = -package parsifal_syntax
EXTRA_OCAMLOPT_LD_FLAGS =
EXTRA_OCAMLC_CC_FLAGS = -package parsifal_syntax
EXTRA_OCAMLC_LD_FLAGS =

BUILD_DIR = build



include ../../Makefile.ocaml


check: all
