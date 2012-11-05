TEST_PROGRAMS = test_answerDump.native test_tls_record.native test_random.native \
                test_pkcs1.native test_rsa_private_key.native test_x509.native \
                test_parsifal.native test_mrt.native test_ssl2.native
PROGRAMS = probe_server.native sslproxy.native serveranswer.native

PREPROCESSORS = preprocess/parsifal_syntax.cmo


all: $(PREPROCESSORS)
	ocamlbuild -cflags -I,+lwt,-I,+cryptokit \
                   -lflags -I,+lwt,-I,+cryptokit \
                   -libs str,unix,nums,bigarray,lwt,lwt-unix,cryptokit \
                   -pp "camlp4o $(PREPROCESSORS)" \
                   $(PROGRAMS) $(TEST_PROGRAMS)

toplevel:
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
	ocamlbuild -clean
	rm -f Makefile.depend Makefile.native-depend $(TEST_PROGRAMS) $(PROGRAMS) \
              *.cmx *.cmi *.cmo *~ *.o