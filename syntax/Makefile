# configurable section
TARGETS =
MLLIBS = parsifal_syntax
LIBNAME = parsifal_syntax

parsifal_syntax_SRCS := parsifalHelpers.ml parsifalSyntax.ml

# comment this line if not using camlp4
USE_CAMLP4 = yes

CC = gcc

# use the following lines to guess .cmxa files from libs names.
# remember, libs are always lowercase
OCAML_LIBS = unix lwt lwt.unix str

# use the following variables to add extra flags (not guessed by ocamlfind)
EXTRA_OCAMLOPT_CC_FLAGS = -package camlp4.extend -package camlp4.quotations.r
EXTRA_OCAMLOPT_LD_FLAGS =
EXTRA_OCAMLC_CC_FLAGS = -package camlp4.extend -package camlp4.quotations.r
EXTRA_OCAMLC_LD_FLAGS =

BUILD_DIR = build


include ../Makefile.ocaml
