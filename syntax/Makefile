all: parsifal_syntax.cma _build/META

parsifal_syntax.cma: parsifal_syntax.mllib parsifalHelpers.ml parsifalSyntax.ml _build
	ocamlbuild -pp "camlp4o pa_extend.cmo q_MLast.cmo" -cflags -I,+camlp4 -lflags -I,+camlp4 parsifal_syntax.cma

_build:
	mkdir -p _build

_build/META: META _build
	cp $< $@

clean:
	ocamlbuild -clean
	rm -f _build
