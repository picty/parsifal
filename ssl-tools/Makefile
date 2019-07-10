# configurable section
TARGETS = mapAnswers x509show probe_server serveranswer sslproxy disturber \
	  extractSessions sslrevproxy

mapAnswers_SRCS := mapAnswers.ml
x509show_SRCS := x509show.ml
probe_server_SRCS := probe_server.ml
serveranswer_SRCS := serveranswer.ml
sslproxy_SRCS := sslproxy.ml
disturber_SRCS := disturber.ml
extractSessions_SRCS := extractSessions.ml
sslrevproxy_SRCS := sslrevproxy.ml

# comment this line if not using camlp4
USE_CAMLP4 = yes

CC = gcc

# use the following lines to guess .cmxa files from libs names.
# remember, libs are always lowercase
OCAML_LIBS = unix result lwt lwt.unix str calendar zarith cryptokit \
	parsifal_syntax parsifal_core parsifal_lwt parsifal_crypto parsifal_net parsifal_ssl

# use the following variables to add extra flags (not guessed by ocamlfind)
EXTRA_OCAMLOPT_CC_FLAGS = -package parsifal_syntax
EXTRA_OCAMLOPT_LD_FLAGS =
EXTRA_OCAMLC_CC_FLAGS = -package parsifal_syntax
EXTRA_OCAMLC_LD_FLAGS =

BUILD_DIR = build


include ../Makefile.ocaml

