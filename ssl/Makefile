# configurable section
TARGETS =
MLLIBS = parsifal_ssl
LIBNAME = parsifal_ssl

parsifal_ssl_SRCS := answerDump.ml tlsEnums.ml tls.ml ssl2.ml tlsCrypto.ml tlsDatabase.ml tlsEngineNG.ml answerDumpUtil.ml

# comment this line if not using camlp4
USE_CAMLP4 = yes

CC = gcc

# use the following lines to guess .cmxa files from libs names.
# remember, libs are always lowercase
OCAML_LIBS = unix result lwt lwt.unix str zarith cryptokit \
	parsifal_syntax parsifal_core parsifal_lwt \
	parsifal_crypto parsifal_net

# use the following variables to add extra flags (not guessed by ocamlfind)
EXTRA_OCAMLOPT_CC_FLAGS = -package parsifal_syntax
EXTRA_OCAMLOPT_LD_FLAGS =
EXTRA_OCAMLC_CC_FLAGS = -package parsifal_syntax
EXTRA_OCAMLC_LD_FLAGS =

BUILD_DIR = build


include ../Makefile.ocaml
