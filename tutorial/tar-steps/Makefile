# configurable section
TARGETS = tar1 tar2 tar3 tar4 tar5 tar6 tar7 tar8

tar1_SRCS := tar1.ml
tar2_SRCS := tar2.ml
tar3_SRCS := tar3.ml
tar4_SRCS := tar4.ml
tar5_SRCS := tar5.ml
tar6_SRCS := tar6.ml
tar7_SRCS := tar7.ml
tar8_SRCS := tar8.ml

# comment this line if not using camlp4
USE_CAMLP4 = yes

CC = gcc

# use the following lines to guess .cmxa files from libs names.
# remember, libs are always lowercase
OCAML_LIBS = unix lwt lwt.unix str parsifal_syntax parsifal_core

# use the following variables to add extra flags (not guessed by ocamlfind)
EXTRA_OCAMLOPT_CC_FLAGS = -package parsifal_syntax
EXTRA_OCAMLOPT_LD_FLAGS =
EXTRA_OCAMLC_CC_FLAGS = -package parsifal_syntax
EXTRA_OCAMLC_LD_FLAGS =

BUILD_DIR = build


include ../../Makefile.ocaml
