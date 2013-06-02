# configurable section
TARGETS = png1 png2 png3 png4 png5 # png6 # png7

png1_SRCS := png1.ml
png2_SRCS := png2.ml
png3_SRCS := png3.ml
png4_SRCS := png4.ml
png5_SRCS := png5.ml
png6_SRCS := png6.ml
png7_SRCS := png7.ml


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
