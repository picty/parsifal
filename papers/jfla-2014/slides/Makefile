FIGURES=../tls_messages.pdf
TEXS=

all: jfla2014.pdf

jfla2014.pdf: %.pdf : jfla2014.tex $(FIGURES) $(TEXS)
	@pdflatex -halt-on-error $< > $*.ltx.out 2>&1 || (cat $*.ltx.out && exit 1) 
	@grep -q '\(There were undefined references\|Label(s) may have changed\)' $*.ltx.out || pdflatex $< > $*.ltx.out 2>&1
	@while grep -q 'Label(s) may have changed' $*.ltx.out; do \
	      pdflatex $< > $*.ltx.out 2>&1; \
	done
	@cat $*.ltx.out
	@rm -f $*.ltx.out

%-fig.pdf: %-fig.eps
	epspdf $<

%-fig.eps: %-fig.ps
	ps2eps $<

%-fig.ps: %-fig.dvi
	dvips -o $@ $<

%-fig.dvi: %-fig.tex
	latex -output-directory $$(dirname $@) $<


clean:
	rm -f img/*-fig.aux img/*-fig.log img/*-fig.dvi img/*-fig.ps img/*-fig.dvi img/*-fig.eps img/*-fig.pdf jfla2014.pdf *.log *.aux *.blg *.bbl *.vrb *.snm *.nav *.out *.toc
