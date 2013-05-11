#!/bin/sh

set -e

PROGNAME=$0

error () {
	echo "Error: $1" >&2
	echo "Usage: $0 <destdir>" >&2
	exit 1
}

DESTDIR=$1

[ -f "$PARSIFAL_DIR/Makefile.ocaml" ] || error "PARSIFAL_DIR variable do not correspond to a directory containing Makefile.ocaml"
[ -f "$PARSIFAL_DIR/Makefile.template" ] || error "PARSIFAL_DIR variable do not correspond to a directory containing Makefile.template"

[ -n "$DESTDIR" ] || error "Invalid destination directory"
[ -f "$DESTDIR" ] && error "Invalid destination directory ($DESTDIR): file already exists"

mkdir "$DESTDIR"
cp "$PARSIFAL_DIR/Makefile.ocaml" "$DESTDIR/Makefile.ocaml"
cp "$PARSIFAL_DIR/Makefile.template" "$DESTDIR/Makefile"
