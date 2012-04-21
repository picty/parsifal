ENUMS = asn1Enums.ml

all: $(ENUMS)

clean:
	rm -f $(ENUMS) *.cmx *.cmi *.cmo *.mk_enums.ml *~ *.o


%.mk_enums.ml: hd_enums.ml %.enums mk_enums.ml
	cat $^ > $@

%Enums.ml: %.mk_enums.ml
	ocaml $< > $@


