ENUMS = asn1Enums.ml tlsEnums.ml
BINRECS = answerDump.ml tls.ml
ASN1RECS = rSAKey.ml x509.ml
SOURCES = asn1Engine.ml parsingEngine.ml lwtParsingEngine.ml dumpingEngine.ml printingEngine.ml \
	$(ENUMS) $(BINRECS) $(CHOICES) $(ASN1RECS) \
	common.ml x509Util.ml\
	tlsUtil.ml tlsContext.ml \
	test_answerDump.ml test_tls_record.ml test_rsa_private_key.ml test_x509.ml test_random.ml

TEST_PROGRAMS = test_answerDump.native test_tls_record.native test_rsa_private_key.native test_x509.native test_random.native test_pkcs1.native
PROGRAMS = $(TEST_PROGRAMS) probe_server.native sslproxy.native answer_stats.native serveranswer.native

all: $(ENUMS) $(BINRECS) $(ASN1RECS)
	ocamlbuild -cflags -I,+lwt,-I,+cryptokit -lflags -I,+lwt,-I,+cryptokit -libs str,unix,nums,bigarray,lwt,lwt-unix,cryptokit test_answerDump.native test_tls_record.native sslproxy.native probe_server.native answer_stats.native test_rsa_private_key.native test_x509.native serveranswer.native test_random.native test_pkcs1.native

toplevel: $(ENUMS) $(BINRECS) $(ASN1RECS)
	ocamlbuild -cflags -I,+lwt,-I,+cryptokit -lflags -I,+lwt,-I,+cryptokit -libs str,unix,nums,bigarray,lwt,lwt-unix,cryptokit util.top
	@echo "rlwrap ./util.top -I _build"

check: $(TEST_PROGRAMS) $(ENUMS) $(BINRECS) $(ASN1RECS)


dep : Makefile.depend Makefile.native-depend


clean:
	rm -f Makefile.depend Makefile.native-depend $(TEST_PROGRAMS) $(ENUMS) $(BINRECS) $(ASN1RECS) \
              *.cmx *.cmi *.cmo *.mk_enums.ml *.mk_binrecs.ml *.mk_choices.ml *.mk_asn1.ml *~ *.o



%.mk_enums.ml: preprocess/hd_enums.ml %.enums common.ml preprocess/mk_enums.ml
	cat $^ > $@

%.ml: %.mk_enums.ml
	ocaml $< > $@


%.mk_binrecs.ml: preprocess/hd_binrecs.ml %.binrecs common.ml preprocess/mk_binrecs.ml
	cat $^ > $@

%.ml: %.mk_binrecs.ml
	ocaml $< > $@


%.mk_asn1.ml: common.ml preprocess/mk_asn1.ml %.asn1
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