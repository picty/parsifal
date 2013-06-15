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

[ -d "$PARSIFAL_DIR/.git" ] || error "$PARSIFAL_DIR do not correspond to a git repo."



# Temporary dir creation

TMPDIR=$(mktemp -d "/tmp/parsifal_XXXXXX")
info "Using temporary dir $TMPDIR"

cd "$PARSIFAL_DIR"

info "Creating parsifal archive"
git archive --format tar -o "$TMPDIR/archive.tar" HEAD .

info "Unfolding the archive"
cd "$TMPDIR"
mkdir build
cd build
if [ -n "$VERBOSE" ]
then tar xvf "../archive.tar"
else tar xf "../archive.tar"
fi

info "Building parsifal project"
make -j 4

info "Checking parsifal"
make check

info "Trying to install parsifal"
BINDIR="$TMPDIR/bin" LIBDIR="$TMPDIR/lib" make install

info "Checking whether the tutorial compiles"
OCAMLPATH="$TMPDIR/lib" make -C tutorial/dns-steps
OCAMLPATH="$TMPDIR/lib" make -C tutorial/tar-steps
OCAMLPATH="$TMPDIR/lib" make -C tutorial/png-steps

echo "Seems OK to me..."


# Cleaning up
[ -n "$VERBOSE" ] || rm -rf "$TMPDIR"
