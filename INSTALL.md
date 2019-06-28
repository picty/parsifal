Installation instructions
=========================

Parsifal currently depends on the following OCaml libraries:

* Lwt (>= 2.4.3)
* Calendar
* Cryptokit (>= 1.10)
* OUnit (for some tests)

To compile Parsifal, you also need the following tools:

* Make
* OCaml 4.02.3
* OCaml-findlib
* OCaml IDL
* krb5
* xz-utils

Since only libcryptokit 1.09 is currently available in Debian stable
(jessie), you might have to rely on opam.


Compilation environment for Debian Stretch
------------------------------------------

To compile Parsifal, you need to ensure you have the following Debian
packages installed:

* git
* make
* ocaml
* ocaml-findlib
* camlidl
* liblwt-ocaml-dev
* libcalendar-ocaml-dev
* libcryptokit-ocaml-dev
* libounit-ocaml-dev
* libkrb5-dev

This can be achieved using the following command line, as root:

    # apt-get install git make ocaml ocaml-findlib camlidl liblwt-ocaml-dev libcalendar-ocaml-dev libcryptokit-ocaml-dev libounit-ocaml-dev libkrb5-dev


Compilation environment using OPAM
----------------------------------

You must first install opam as root, as well as some required dependencies:

    # apt-get install opam
    # apt-get install git m4 libkrb5-dev pkg-config zlib1g-dev libgmp-dev

The rest of the procedure can be done as an unprivileged user:

    % opam init --comp 4.02.3
    % opam install ocamlfind camlp4 lwt=2.5.2 calendar cryptokit=1.10 ounit camlidl



Actual compilation instructions
-------------------------------

Assuming you want to compile parsifal in the ~/parsifal directory, you
can then type in the following commands:

    % cd
    % git clone https://github.com/ANSSI-FR/parsifal
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

With opam, only OCaml 4.02.3 has been tested. Other versions could
work, but compilation will fail with the latest one, due to the
bytes/string evolution in recent versions.

Since Cryptokit 1.11 depends on ZArith and Lwt 2.6.0 depends on
Result, the compilation fails if you use the latest versions.  The
Makefile should be adapted to handle this properly.