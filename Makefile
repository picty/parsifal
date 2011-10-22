all:
	ocamlbuild facesl.native asn1parse.native test_asn1.native test_asn1Parser.native test_crypto.native test_answerDump.native test_socket.native test_tls.native
