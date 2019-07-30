#!/bin/sh

set -e

docker build -t parsifal-test:opam2-ocaml-4.06 --build-arg OCAML_VERSION=4.06 opam2
docker build -t parsifal-test:opam2-ocaml-4.05 --build-arg OCAML_VERSION=4.05 opam2
docker build -t parsifal-test:buster buster

for i in opam2-ocaml-4.06 opam2-ocaml-4.05 buster; do
    docker tag parsifal-test:"$i" pictyeye/parsifal-test:"$i"
done

for i in opam2-ocaml-4.06 opam2-ocaml-4.05 buster; do
    docker push pictyeye/parsifal-test:"$i"
done
