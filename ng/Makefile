ENUMS = asn1Enums.ml
BINRECS = answerDump.ml
ASN1RECS = rSAPrivateKey.ml
SOURCES = asn1Engine.ml parsingEngine.ml rSAPrivateKey.ml test_answerDump.ml

TEST_PROGRAMS = test_answerDump.native


all: $(ENUMS)

dep : Makefile.depend


clean:
	rm -f Makefile.depend $(ENUMS) $(BINRECS) $(ASN1RECS) *.cmx *.cmi *.cmo *.mk_enums.ml *.mk_binrecs.ml *.mk_asn1.ml *~ *.o



%.mk_enums.ml: preprocess/hd_enums.ml %.enums preprocess/mk_enums.ml
	cat $^ > $@

%.ml: %.mk_enums.ml
	ocaml $< > $@


%.mk_binrecs.ml: preprocess/hd_binrecs.ml %.binrecs preprocess/mk_binrecs.ml
	cat $^ > $@

%.ml: %.mk_binrecs.ml
	ocaml $< > $@


%.mk_asn1.ml: preprocess/hd_asn1.ml %.asn1 preprocess/mk_asn1.ml
	cat $^ > $@

%.ml: %.mk_asn1.ml
	ocaml $< > $@



%.cmx: %.ml
	ocamlopt -c $^

%.cmo: %.ml
	ocamlc -c $^


Makefile.depend: Makefile $(ENUMS) $(BINRECS) $(ASN1RECS) $(SOURCES)
	ocamldep $^ > Makefile.depend

-include Makefile.depend