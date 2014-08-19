# configurable section
TARGETS = asn1parse picodig parsifal

asn1parse_SRCS := asn1parse.ml
picodig_SRCS := picodig.ml
parsifal_SRCS := parsifal_main.ml

# comment this line if not using camlp4
# USE_CAMLP4 = yes

CC = gcc

# use the following lines to guess .cmxa files from libs names.
# remember, libs are always lowercase
OCAML_LIBS = unix lwt lwt.unix str cryptokit parsifal_syntax parsifal_core parsifal_lwt parsifal_crypto \
	parsifal_net parsifal_formats parsifal_ssl parsifal_kerby parsifal_pgp

CAMLIDL_DIR = `$(OCAMLFIND) query camlidl`

# use the following variables to add extra flags (not guessed by ocamlfind)
EXTRA_OCAMLOPT_CC_FLAGS =
# EXTRA_OCAMLOPT_CC_FLAGS = -package parsifal_syntax
EXTRA_OCAMLOPT_LD_FLAGS = ../kerby/build/krb5_stubs.o ../kerby/build/krb5_functions.o -cclib -lk5crypto -ccopt "-L $(CAMLIDL_DIR)" -cclib -lcamlidl -cclib -lmylzma -cclib -lmytiano -ccopt -Lbuild/
EXTRA_OCAMLC_CC_FLAGS =
# EXTRA_OCAMLC_CC_FLAGS = -package parsifal_syntax
EXTRA_OCAMLC_LD_FLAGS =

BUILD_DIR = build


include ../Makefile.ocaml

