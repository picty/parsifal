# configurable section
TARGETS = csr1 csr2 csr3

csr1_SRCS := csr1.ml
csr2_SRCS := csr2.ml
csr3_SRCS := csr3.ml

# comment this line if not using camlp4
USE_CAMLP4 = yes

CC = gcc

# use the following lines to guess .cmxa files from libs names.
# remember, libs are always lowercase
OCAML_LIBS = unix str calendar zarith cryptokit parsifal_syntax parsifal_core parsifal_crypto

# use the following variables to add extra flags (not guessed by ocamlfind)
EXTRA_OCAMLOPT_CC_FLAGS = -package parsifal_syntax
EXTRA_OCAMLOPT_LD_FLAGS =
EXTRA_OCAMLC_CC_FLAGS = -package parsifal_syntax
EXTRA_OCAMLC_LD_FLAGS =

BUILD_DIR = build


include ../../Makefile.ocaml

