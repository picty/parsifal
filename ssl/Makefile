# configurable section
TARGETS =
MLLIBS = parsifal_ssl

parsifal_ssl_SRCS := dSAKey.ml rSAKey.ml x509Basics.ml x509Extensions.ml cryptoUtil.ml \
                     randomEngine.ml pkcs1.ml x509.ml ocsp.ml answerDump.ml \
                     tlsEnums.ml tls.ml ssl2.ml tlsDatabase.ml tlsUtil.ml tlsEngine.ml
		# x509CertificateStore.ml

# comment this line if not using camlp4
USE_CAMLP4 = yes

CC = gcc

# use the following lines to guess .cmxa files from libs names.
# remember, libs are always lowercase
OCAML_LIBS = unix lwt lwt.unix str cryptokit parsifal_syntax parsifal_core parsifal_net

# use the following variables to add extra flags (not guessed by ocamlfind)
EXTRA_OCAMLOPT_CC_FLAGS = -package parsifal_syntax
EXTRA_OCAMLOPT_LD_FLAGS =
EXTRA_OCAMLC_CC_FLAGS = -package parsifal_syntax
EXTRA_OCAMLC_LD_FLAGS =

BUILD_DIR = build


include ../Makefile.ocaml
