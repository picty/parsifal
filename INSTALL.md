Installation instructions
=========================

Parsifal currently depends on the following OCaml libraries:

* Lwt
* Calendar
* Cryptokit
* OUnit (for some tests)

To compile Parsifal, you also need the following tools:

* Make
* OCaml
* OCaml-findlib
* OCaml IDL
* krb5
* xz-utils


Compilation environment for Debian Buster
-----------------------------------------

To compile Parsifal, you need to ensure you have the following Debian
packages installed:

* git
* make
* ocaml
* ocaml-findlib
* camlidl
* camlp4
* liblwt-ocaml-dev
* libcalendar-ocaml-dev
* libcryptokit-ocaml-dev
* libounit-ocaml-dev
* libkrb5-dev

This can be achieved using the following command line, as root:

    # apt-get install git make ocaml ocaml-findlib camlidl camlp4 liblwt-ocaml-dev libcalendar-ocaml-dev libcryptokit-ocaml-dev libounit-ocaml-dev libkrb5-dev

Parsifal v0.3 is compatible with Debian Stretch, but the current
version does not compile on Stretch or earlier versions of Debian. If
you encounter such problems, you might need to rely on opam.


Compilation environment using OPAM
----------------------------------

You must first install some required dependencies:

    # apt-get install git m4 libkrb5-dev pkg-config zlib1g-dev libgmp-dev

The rest of the procedure can be done as an unprivileged user:

    % opam install ocamlfind camlp4 lwt calendar cryptokit ounit camlidl



Actual compilation instructions
-------------------------------

Assuming you want to compile parsifal in the ~/parsifal directory, you
can then type in the following commands:

    % cd
    % git clone https://github.com/picty/parsifal
    % cd parsifal
    % make

To install the libraries and the binaries in standard directories, you
must execute the following command as root:

    # make install

Alternatively, to install the libraries and the binaries in a custom
location, for example in subdirectories of your home directory:

    % LIBDIR=$HOME/.ocamlpath BINDIR=$HOME/bin make install


Notes
-----

These instructions have been tested with Debian Buster, and with opam
1.2 (and OCaml 4.05.0 and 4.06.0).

It could also work with other versions of opam and of the compiler.
