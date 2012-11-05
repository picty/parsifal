TEST_PROGRAMS = test_parsifal.native

PREPROCESSORS = parsifal_syntax.cmo


all: $(PREPROCESSORS)
	ocamlbuild -cflags -I,+lwt \
                   -lflags -I,+lwt \
                   -libs str,unix,nums,bigarray,lwt,lwt-unix \
                   -pp "camlp4o $(PREPROCESSORS)" \
                   $(TEST_PROGRAMS)

toplevel:
	ocamlbuild -cflags -I,+lwt \
                   -lflags -I,+lwt \
                   -libs str,unix,nums,bigarray,lwt,lwt-unix \
                   -pp "camlp4o $(PREPROCESSORS)" \
                   util.top
	@echo "rlwrap ./util.top -I _build"


preprocessors: $(PREPROCESSORS)

%.cmo: %.ml
	ocamlbuild -pp "camlp4o pa_extend.cmo q_MLast.cmo" -cflags -I,+camlp4 -lflags -I,+camlp4 $@


clean:
	ocamlbuild -clean
	rm -f Makefile.depend Makefile.native-depend $(TEST_PROGRAMS) $(PROGRAMS) \
              *.cmx *.cmi *.cmo *~ *.o
