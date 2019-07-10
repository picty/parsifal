# configurable section
TARGETS =
MLLIBS = parsifal_lwt
LIBNAME = parsifal_lwt

parsifal_lwt_SRCS := lwt_semaphore.ml lwtUtil.ml

# comment this line if not using camlp4
USE_CAMLP4 = yes

CC = gcc

# use the following lines to guess .cmxa files from libs names.
# remember, libs are always lowercase
OCAML_LIBS = unix result lwt lwt.unix str parsifal_syntax parsifal_core

# use the following variables to add extra flags (not guessed by ocamlfind)
EXTRA_OCAMLOPT_CC_FLAGS = -package parsifal_syntax
EXTRA_OCAMLOPT_LD_FLAGS =
EXTRA_OCAMLC_CC_FLAGS = -package parsifal_syntax
EXTRA_OCAMLC_LD_FLAGS =

BUILD_DIR = build


include ../Makefile.ocaml
