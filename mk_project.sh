#!/bin/bash

set -e

PROGNAME=$0

error () {
	echo "Error: $1" >&2
	echo "Usage: $0 <destdir>" >&2
	exit 1
}

DESTDIR=$1
PROJECT_NAME="$(basename "$DESTDIR")"

[ -z "$PARSIFAL_DIR" ] && PARSIFAL_DIR="$(dirname "$PROGNAME")"

[ -f "$PARSIFAL_DIR/Makefile.ocaml" ] || error "PARSIFAL_DIR variable do not correspond to a directory containing Makefile.ocaml"
[ -f "$PARSIFAL_DIR/Makefile.template" ] || error "PARSIFAL_DIR variable do not correspond to a directory containing Makefile.template"

[ -n "$DESTDIR" ] || error "Invalid destination directory"
[ -f "$DESTDIR" ] && error "Invalid destination directory ($DESTDIR): file already exists"
[ "$(echo -n "$PROJECT_NAME" | sed 's/^[a-z][a-zA-Z0-9_]*$//g' | wc -c)" -eq 0 ] || error "The file should only contain letters, figures and underscores, and start with a lowercase letter"

mkdir "$DESTDIR"
cp "$PARSIFAL_DIR/Makefile.ocaml" "$DESTDIR/Makefile.ocaml"
sed "s/project/$PROJECT_NAME/g" "$PARSIFAL_DIR/Makefile.template" > "$DESTDIR/Makefile"
cat > "$DESTDIR/$PROJECT_NAME.ml" << EOF
open Parsifal

let _ =
  print_endline "Hello, world!"
EOF
