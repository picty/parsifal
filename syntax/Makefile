LIBDIR ?= /usr/local/lib/ocaml
LIBNAME = parsifal_syntax

all: _build/parsifal_syntax.cma _build/META

_build/parsifal_syntax.cma: parsifal_syntax.mllib parsifalHelpers.ml parsifalSyntax.ml _build
	ocamlbuild -pp "camlp4o pa_extend.cmo q_MLast.cmo" -cflags -I,+camlp4 -lflags -I,+camlp4 parsifal_syntax.cma

_build:
	mkdir -p _build

_build/META: META _build
	cp $< $@

install: _build/parsifal_syntax.cma _build/META
	 @for f in _build/parsifal_syntax.cma _build/META; do \
	   echo "Installing $$(basename $$f) -> $(LIBDIR)/$(LIBNAME)/$$(basename $$f)"; \
	   install -D -m 0644 "$$f" "$(LIBDIR)/$(LIBNAME)$(DESTDIR)/$$(basename $$f)"; \
	 done


clean:
	ocamlbuild -clean
	rm -f _build
