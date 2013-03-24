# configurable section
TARGETS = mapAnswers asn1parse x509show probe_server serveranswer sslproxy disturber \
	  extractSessions
	# check_sslclient check_sslserver

mapAnswers_SRCS := mapAnswers.ml
asn1parse_SRCS := asn1parse.ml
x509show_SRCS := x509show.ml
probe_server_SRCS := probe_server.ml
serveranswer_SRCS := serveranswer.ml
sslproxy_SRCS := sslproxy.ml
disturber_SRCS := disturber.ml
extractSessions_SRCS := extractSessions.ml
# check_sslclient_SRCS := check_sslclient.ml
# check_sslserver_SRCS := check_sslserver.ml

# comment this line if not using camlp4
USE_CAMLP4 = yes

CC = gcc

# use the following lines to guess .cmxa files from libs names.
# remember, libs are always lowercase
OCAML_LIBS = unix lwt lwt.unix str cryptokit parsifal_syntax parsifal_core parsifal_net parsifal_ssl

# use the following variables to add extra flags (not guessed by ocamlfind)
EXTRA_OCAMLOPT_CC_FLAGS = -package parsifal_syntax
EXTRA_OCAMLOPT_LD_FLAGS =
EXTRA_OCAMLC_CC_FLAGS = -package parsifal_syntax
EXTRA_OCAMLC_LD_FLAGS =

BUILD_DIR = build


include ../Makefile.ocaml

