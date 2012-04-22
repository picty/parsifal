ENUMS = asn1Enums.ml answerDump.ml

all: $(ENUMS)

clean:
	rm -f $(ENUMS) *.cmx *.cmi *.cmo *.mk_enums.ml *.mk_binrecs.ml *~ *.o


%.mk_enums.ml: hd_enums.ml %.enums mk_enums.ml
	cat $^ > $@

%.ml: %.mk_enums.ml
	ocaml $< > $@


%.mk_binrecs.ml: hd_binrecs.ml %.binrecs mk_binrecs.ml
	cat $^ > $@

%.ml: %.mk_binrecs.ml
	ocaml $< > $@
