# configurable section
TARGETS =
MLLIBS = parsifal_crypto
LIBNAME = parsifal_crypto

parsifal_crypto_SRCS := dHKey.ml dSAKey.ml eCKey.ml x509Basics.ml x509Extensions.ml cryptoUtil.ml \
		        randomEngine.ml pkcs1.ml x509.ml pkcs7.ml x509Util.ml crl.ml

# comment this line if not using camlp4
USE_CAMLP4 = yes

CC = gcc

# use the following lines to guess .cmxa files from libs names.
# remember, libs are always lowercase
OCAML_LIBS = unix str calendar zarith cryptokit parsifal_syntax parsifal_core

# use the following variables to add extra flags (not guessed by ocamlfind)
EXTRA_OCAMLOPT_CC_FLAGS = -package parsifal_syntax
EXTRA_OCAMLOPT_LD_FLAGS =
EXTRA_OCAMLC_CC_FLAGS = -package parsifal_syntax
EXTRA_OCAMLC_LD_FLAGS =

BUILD_DIR = build


include ../Makefile.ocaml
