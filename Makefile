all:
	ocamlbuild -libs nums -Is common,parser,asn1,tls,formats,tools asn1parse.native test_asn1.native test_asn1Parser.native test_tls.native test_answerDump.native

clean:
	ocamlbuild -clean
