LONG=OlivierLevillain--Parsifal.pdf
SHORT=OlivierLevillain--Parsifal--short.pdf
BIBLIO=biblio.bib rfc.bib


all: $(LONG) $(SHORT)

OlivierLevillain--Parsifal.pdf:	OlivierLevillain--Parsifal.tex $(BIBLIO)
	pdflatex $< && bibtex OlivierLevillain--Parsifal.aux && pdflatex $< && pdflatex $<

OlivierLevillain--Parsifal--short.pdf: OlivierLevillain--Parsifal--short.tex
	pdflatex $< && pdflatex $<

clean:
	rm -f *.aux *.bbl *.log *.bbl $(LONG) $(SHORT)
