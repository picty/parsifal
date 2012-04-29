all:
	ocamlbuild -cflags -I,+lwt -lflags -I,+lwt -libs unix,bigarray,lwt,lwt-unix facesl.native asn1parse.native test_asn1.native test_asn1Parser.native test_crypto.native test_answerDump.native test_socket.native test_record.native testBgp.native test_x509.native sslproxy.native x509Check.native extract_ciphersuites.native extract_moduli.native extract_subjects.native extract_csv.native test_ssl2.native extract_cert_csv.native describe_client_hello.native describe_client_hello_sslv2.native classify_certchains.native

pouet:
	ocamlbuild classify_certchains.native

clean:
	ocamlbuild -clean
