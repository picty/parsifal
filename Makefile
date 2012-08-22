ASN1RECS = rSAKey.ml x509.ml

TEST_PROGRAMS = test_answerDump.native test_tls_record.native test_random.native \
                test_pkcs1.native test_rsa_private_key.native test_x509.native \
                test_camlp4_stuff.native test_mrt.native test_ssl2.native
PROGRAMS = probe_server.native sslproxy.native serveranswer.native

PREPROCESSORS = preprocess/mk_enums.cmo preprocess/mk_records.cmo


all: $(ASN1RECS) $(PREPROCESSORS)
	ocamlbuild -cflags -I,+lwt,-I,+cryptokit \
                   -lflags -I,+lwt,-I,+cryptokit \
                   -libs str,unix,nums,bigarray,lwt,lwt-unix,cryptokit \
                   -pp "camlp4o $(PREPROCESSORS)" \
                   $(PROGRAMS) $(TEST_PROGRAMS)

toplevel: $(ASN1RECS)
	ocamlbuild -cflags -I,+lwt,-I,+cryptokit \
                   -lflags -I,+lwt,-I,+cryptokit \
                   -libs str,unix,nums,bigarray,lwt,lwt-unix,cryptokit \
                   -pp "camlp4o $(PREPROCESSORS)" \
                   util.top
	@echo "rlwrap ./util.top -I _build"

check: $(TEST_PROGRAMS) $(ASN1RECS)


preprocessors: $(PREPROCESSORS)

preprocess/%.cmo: preprocess/%.ml
	ocamlbuild -pp "camlp4o pa_extend.cmo q_MLast.cmo" -cflags -I,+camlp4 -lflags -I,+camlp4 $@


clean:
	ocamlbuild -build-dir .build.main -clean
	ocamlbuild -build-dir .build.toplevel -clean
	rm -f Makefile.depend Makefile.native-depend $(TEST_PROGRAMS) $(PROGRAMS) $(ASN1RECS) \
              *.cmx *.cmi *.cmo *.mk_binrecs.ml *.mk_choices.ml *.mk_asn1.ml *~ *.o



# Specific dependencies
%.mk_asn1.ml: common.ml preprocess/mk_asn1.ml %.asn1
	cat $^ > $@

%.ml: %.mk_asn1.ml
	ocaml $< > $@

