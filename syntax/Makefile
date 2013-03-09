all: parsifal-syntax.cma

parsifal-syntax.cma: parsifal-syntax.mllib parsifalHelpers.ml parsifalSyntax.ml
	ocamlbuild -pp "camlp4o pa_extend.cmo q_MLast.cmo" -cflags -I,+camlp4 -lflags -I,+camlp4 parsifal-syntax.cma

install: parsifal-syntax.cma
	cp _build/parsifal-syntax.cma ../usrlibocaml/

clean:
	ocamlbuild -clean
	rm -f _build
