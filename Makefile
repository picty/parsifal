all:
	ocamlbuild -libs unix,str -Is common,parser,asn1,tls,formats,tools,map asn1parse.native test_asn1.native test_asn1Parser.native test_tls.native test_answerDump.native test_socket.native facesl.native

clean:
	ocamlbuild -clean
