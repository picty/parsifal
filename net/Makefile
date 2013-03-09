# configurable section
TARGETS =
MLLIBS = parsifal_net

parsifal_net_SRCS := dns.ml pcap.ml

# x509CertificateStore.ml

# comment this line if not using camlp4
USE_CAMLP4 = yes

CC = gcc

# use the following lines to guess .cmxa files from libs names.
# remember, libs are always lowercase
OCAML_LIBS = unix lwt lwt.unix str cryptokit parsifal.core

# use the following variables to add extra flags (not guessed by ocamlfind)
EXTRA_OCAMLOPT_CC_FLAGS = -package parsifal.syntax
EXTRA_OCAMLOPT_LD_FLAGS =
EXTRA_OCAMLC_CC_FLAGS = -package parsifal.syntax
EXTRA_OCAMLC_LD_FLAGS =

BUILD_DIR = build


include ../Makefile.ocaml


install: parsifal_net.cma parsifal_net.cmxa parsifal_net.a
	cp parsifal_net.cma ../usrlibocaml/parsifal-net.cma
	cp parsifal_net.cmxa ../usrlibocaml/parsifal-net.cmxa
	cp parsifal_net.a ../usrlibocaml/parsifal-net.a
	cp build/*.cmi ../usrlibocaml/
