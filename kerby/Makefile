# configurable section
MLLIBS = parsifal_kerby
LIBNAME = parsifal_kerby

parsifal_kerby_SRCS := krb5.ml kerbyContainers.ml kerberosTypes.ml padata.ml kerby.ml keytab.ml

# comment this line if not using camlp4
USE_CAMLP4 = yes

CC = gcc

# use the following lines to guess .cmxa files from libs names.
# remember, libs are always lowercase
OCAML_LIBS = unix str cryptokit parsifal_syntax parsifal_core parsifal_net parsifal_crypto

# use the following variables to add extra flags (not guessed by ocamlfind)
EXTRA_OCAMLOPT_CC_FLAGS = -package parsifal_syntax
EXTRA_OCAMLOPT_LD_FLAGS = build/krb5_stubs.o build/krb5_functions.o -cclib -lk5crypto -cclib -lcamlidl
EXTRA_OCAMLC_CC_FLAGS = -package parsifal_syntax
EXTRA_OCAMLC_LD_FLAGS = -custom build/krb5_stubs.o build/krb5_functions.o -cclib -lk5crypto -cclib -lcamlidl

BUILD_DIR = build


include ../Makefile.ocaml


build/krb5_stubs.o: krb5_stubs.c
	gcc -DDEBUG -Wall -c -o $@ $<

build/krb5_functions.o: krb5_functions.c
	gcc -DDEBUG -Wall -c -o $@ $<

build/krb5.cmo: build/krb5_stubs.o build/krb5_functions.o
build/krb5.cmx: build/krb5_stubs.o build/krb5_functions.o

