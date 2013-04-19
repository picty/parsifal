# configurable section
TARGETS = dns1 dns2 dns3 dns4 dns5 dns6 dns7 # dns8 dns9

dns1_SRCS := dns1.ml
dns2_SRCS := dns2.ml
dns3_SRCS := dns3.ml
dns4_SRCS := dns4.ml
dns5_SRCS := dns5.ml
dns6_SRCS := dns6.ml
dns7_SRCS := dns7.ml
# dns8_SRCS := dns8.ml
# dns9_SRCS := dns9.ml

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
