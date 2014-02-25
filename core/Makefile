# configurable section
TARGETS =
MLLIBS = parsifal_core
LIBNAME = parsifal_core

parsifal_core_SRCS := pOutput.ml parsifal.ml basePTypes.ml pTypes.ml asn1Engine.ml asn1PTypes.ml base64.ml \
                      getopt.ml protobuf.ml json.ml crc.ml zLib.ml

# comment this line if not using camlp4
USE_CAMLP4 = yes

CC = gcc

# use the following lines to guess .cmxa files from libs names.
# remember, libs are always lowercase
OCAML_LIBS = unix str parsifal_syntax

# use the following variables to add extra flags (not guessed by ocamlfind)
EXTRA_OCAMLOPT_CC_FLAGS = -package parsifal_syntax
EXTRA_OCAMLOPT_LD_FLAGS =
EXTRA_OCAMLC_CC_FLAGS = -package parsifal_syntax
EXTRA_OCAMLC_LD_FLAGS =

BUILD_DIR = build


include ../Makefile.ocaml
