ENUMS = asn1Enums.ml tlsEnums.ml
BINRECS = answerDump.ml tls.ml tlsHandshake.ml
CHOICES = tlsChoices-ng.ml
ASN1RECS = rSAPrivateKey.ml
SOURCES = asn1Engine.ml parsingEngine.ml lwtParsingEngine.ml dumpingEngine.ml printingEngine.ml \
	$(ENUMS) $(BINRECS) $(CHOICES) $(ASN1RECS) \
	common.ml \
	tlsChoices.ml \
	test_answerDump.ml test_tls_record.ml

TEST_PROGRAMS = test_answerDump.native test_tls_record.native
PROGRAMS = $(TEST_PROGRAMS)

all:

check: $(TEST_PROGRAMS) $(ENUMS) $(BINRECS) $(CHOICES) $(ASN1RECS)


dep : Makefile.depend Makefile.native-depend


clean:
	rm -f Makefile.depend Makefile.native-depend $(TEST_PROGRAMS) $(ENUMS) $(BINRECS) $(CHOICES) $(ASN1RECS) \
              *.cmx *.cmi *.cmo *.mk_enums.ml *.mk_binrecs.ml *.mk_choices.ml *.mk_asn1.ml *~ *.o



%.mk_enums.ml: preprocess/hd_enums.ml %.enums preprocess/mk_enums.ml
	cat $^ > $@

%.ml: %.mk_enums.ml
	ocaml $< > $@


%.mk_binrecs.ml: preprocess/hd_binrecs.ml %.binrecs preprocess/mk_binrecs.ml
	cat $^ > $@

%.ml: %.mk_binrecs.ml
	ocaml $< > $@


%.mk_choices.ml: preprocess/hd_choices.ml %.choices preprocess/mk_choices.ml
	cat $^ > $@

%.ml: %.mk_choices.ml
	ocaml $< > $@


%.mk_asn1.ml: preprocess/hd_asn1.ml %.asn1 preprocess/mk_asn1.ml
	cat $^ > $@

%.ml: %.mk_asn1.ml
	ocaml $< > $@



%.cmx: %.ml
	ocamlopt -c $^

%.cmo: %.ml
	ocamlc -c $^

%.native:
	ocamlopt -o $@ $^


Makefile.depend: Makefile $(ENUMS) $(BINRECS) $(ASN1RECS) $(SOURCES)
	ocamldep $^ > $@

Makefile.native-depend: Makefile.depend
	./native_deps.py $^ $(PROGRAMS) > $@

-include Makefile.depend
-include Makefile.native-depend