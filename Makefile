TEST_PROGRAMS = test_answerDump.native test_tls_record.native test_random.native \
                test_pkcs1.native test_rsa_private_key.native \
                test_parsifal.native test_mrt.native test_ssl2.native test_tar.native \
                test_ocsp.native test_pe.native test_pcap.native test_dns.native
PROGRAMS = probe_server.native sslproxy.native serveranswer.native \
           x509show.native asn1parse.native

PREPROCESSORS = preprocess/parsifal_syntax.cma


all: $(PREPROCESSORS)
	ocamlbuild -j 0 -cflags -I,+lwt,-I,+cryptokit \
                   -lflags -I,+lwt,-I,+cryptokit \
                   -libs str,unix,nums,bigarray,lwt,lwt-unix,cryptokit \
                   -pp "camlp4o $(PREPROCESSORS)" \
                   $(PROGRAMS) $(TEST_PROGRAMS)

toplevel:
	ocamlbuild -j 0 -cflags -I,+lwt,-I,+cryptokit \
                   -lflags -I,+lwt,-I,+cryptokit \
                   -libs str,unix,nums,bigarray,lwt,lwt-unix,cryptokit \
                   -pp "camlp4o $(PREPROCESSORS)" \
                   util.top
	@echo "rlwrap ./util.top -I _build"

check: $(TEST_PROGRAMS) $(ASN1RECS)


preprocessors: $(PREPROCESSORS)

preprocess/%.cma: preprocess/%.mllib
	ocamlbuild -j 0 -pp "camlp4o pa_extend.cmo q_MLast.cmo" -cflags -I,+camlp4 -lflags -I,+camlp4 $@


clean:
	ocamlbuild -clean
	rm -f Makefile.depend Makefile.native-depend $(TEST_PROGRAMS) $(PROGRAMS) \
              *.cmx *.cmi *.cmo *~ *.o
