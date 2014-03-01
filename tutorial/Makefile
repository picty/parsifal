all: tutorial.pdf

tutorial.pdf: tutorial.tex
	@pdflatex -halt-on-error $< > $*.ltx.out 2>&1 || (cat $*.ltx.out && exit 1) 
	@grep -q '\(There were undefined references\|Label(s) may have changed\)' $*.ltx.out || pdflatex $< > $*.ltx.out 2>&1
	@while grep -q 'Label(s) may have changed' $*.ltx.out; do \
	      pdflatex $< > $*.ltx.out 2>&1; \
	done
	@cat $*.ltx.out
	@rm -f $*.ltx.out


clean:
	rm -f tutorial.pdf *.log *.aux *.blg *.bbl *.vrb *.snm *.nav *.out *.toc
