README
======

Parsifal is an OCaml-based parsing engine.

Parsifal is a collection of binary parsers and tools. The development
is at an early stage (which explains the 0.1 version).

There are several file formats or network protocols currently (at
least partially) described:

  * X.509 certificates
  * SSL/TLS messages
  * DNS messages
  * MRT/BGP messages
  * Portable Executables
  * UEFI Firmwares
  * PKCS#1 keys and containers
  * PKCS#7 containers
  * Kerberos messages
  * OpenPGP messages
  * DVI documents
  * PNG images
  * PCAP/IP/TCP/UDP rudimentary support
  * NTP messages


Here is the content of the various directories of parsifal repository:

  * syntax/ contains the preprocessor used to generate automatically
    types and functions
  * core/ is the standard parsifal library (common PTypes, input
    structures, useful functions to print values)
  * crypto/ contains the cryptographic functions and object
    descriptions:
    * hash function (MD5, SHA1 and SHA256)
    * Diffie-Hellman keys
    * DSA keys
    * RSA keys and implementation (PKCS#1)
    * PRNG
    * X.509 certificates
    * PKCS#7 containers
  * net/ describes some formats/protcols related to networking
    * PCAP/IP/TCP/UDP trivial support
    * BGP/MRT messages
    * DNS messages
    * NTP messages
  * ssl/ is a first step towards a functionnal TLS stack. For the
    moment, it contains the description of handshake messages and some
    useful functions to produce and read TLS records.
  * formats/ describes some file formats
    * DVI (DeVice Independant files)
    * Portable Executable
    * UEFI Firmware Volumes
    * TAR archives
    * PNG images
  * kerby/ is a collection of files to parse Kerberos messages
  * pci/ is about PCI Expansion ROMs

  * ssl-tools/ contains SSL/TLS useful programs
  * openpgp-tools/ contains a program to parse PGP containers
  * tools/ contains several tools like asn1parse or parsifal, which
    allows to parse and explore described PTypes

Moreover, several test/ and unit/ exist, that contain unfinished
programs and unit tests. usrlibocaml/ is only there to ease the
compilation process.

Finally, tutorial/ and papers/ contain the documentation and submitted
papers describing parsifal, whereas docs contains RFCs and official
specs.


A Docker image is available in the pictyeye/parsifal repository on Docker
Hub. It allows to use parsifal tools, such as probe_server:

    % docker run -ti --rm pictyeye/parsifal
    root@2cdbe79c9809:/# probe_server -H www.perdu.com extract-certs
    Saved 2 certificates
