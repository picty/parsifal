FROM ocaml/opam2

RUN sudo apt-get install -y git m4 libkrb5-dev pkg-config zlib1g-dev libgmp-dev

ARG OCAML_VERSION=4.05
RUN opam switch ${OCAML_VERSION} && eval $(opam env) && opam install ocamlfind camlp4 lwt calendar cryptokit ounit camlidl
