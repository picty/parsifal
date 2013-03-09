# configurable section
TARGETS =
MLLIBS = parsifal_core

parsifal_core_SRCS := parsifal.ml basePTypes.ml pTypes.ml asn1Engine.ml asn1PTypes.ml

# comment this line if not using camlp4
USE_CAMLP4 = yes

CC = gcc

# use the following lines to guess .cmxa files from libs names.
# remember, libs are always lowercase
OCAML_LIBS = unix lwt lwt.unix str cryptokit

# use the following variables to add extra flags (not guessed by ocamlfind)
EXTRA_OCAMLOPT_CC_FLAGS = -package parsifal.syntax
EXTRA_OCAMLOPT_LD_FLAGS =
EXTRA_OCAMLC_CC_FLAGS = -package parsifal.syntax
EXTRA_OCAMLC_LD_FLAGS =

BUILD_DIR = build


include Makefile.ocaml


install: parsifal_core.cma parsifal_core.cmxa parsifal_core.a
	cp parsifal_core.cma ../usrlibocaml/parsifal-core.cma
	cp parsifal_core.cmxa ../usrlibocaml/parsifal-core.cmxa
	cp parsifal_core.a ../usrlibocaml/parsifal-core.a
	cp build/*.cmi ../usrlibocaml/