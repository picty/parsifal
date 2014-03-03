#!/bin/bash

set -e


# Script initialization

PROGNAME=$0

error () {
	echo "Error: $1" >&2
	echo "Usage: $0 [parsifal dir]" >&2
	exit 1
}

info () {
    [ -z "$VERBOSE" ] || echo "[INFO] $1" >&2
}

PARSIFAL_DIR=$1
[ -z "$PARSIFAL_DIR" ] && PARSIFAL_DIR="$(dirname "$PROGNAME")"

[ -f "$PARSIFAL_DIR/Makefile.ocaml" ] || error "$PARSIFAL_DIR does not seem to be a directory containing Parsifal."



info "Compiling everything if necessary"
cd "$PARSIFAL_DIR"
make libs
cd -

rlwrap ocaml -init "$PARSIFAL_DIR/toplevel.ml" \
	-I /usr/lib/ocaml/lwt \
	-I /usr/lib/ocaml/cryptokit \
	-I "$PARSIFAL_DIR/usrlibocaml/parsifal_core" \
	-I "$PARSIFAL_DIR/usrlibocaml/parsifal_crypto" \
	-I "$PARSIFAL_DIR/usrlibocaml/parsifal_net" \
	-I "$PARSIFAL_DIR/usrlibocaml/parsifal_formats" \
	-I "$PARSIFAL_DIR/usrlibocaml/parsifal_lwt" \
	-I "$PARSIFAL_DIR/usrlibocaml/parsifal_ssl" \
	-I "$PARSIFAL_DIR/usrlibocaml/parsifal_pgp" \
	unix.cma nums.cma bigarray.cma lwt.cma cryptokit.cma lwt-unix.cma \
	"$PARSIFAL_DIR"/usrlibocaml/parsifal_{core,crypto,net,formats,lwt,ssl,pgp}/*.cma
