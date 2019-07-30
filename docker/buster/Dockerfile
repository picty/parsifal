FROM debian:buster

RUN apt-get update
RUN apt-get update && apt install --no-install-recommends -y git make
RUN apt-get update && apt install --no-install-recommends -y ocaml ocaml-findlib camlidl camlp4 liblwt-ocaml-dev libcalendar-ocaml-dev libcryptokit-ocaml-dev libounit-ocaml-dev libkrb5-dev
RUN apt-get update && apt install --no-install-recommends -y ca-certificates
RUN apt clean
