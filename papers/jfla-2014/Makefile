TEXFILENAME=OlivierLevillain--Parsifal

all:
	pdflatex $(TEXFILENAME).tex && bibtex $(TEXFILENAME).aux && pdflatex $(TEXFILENAME).tex && pdflatex $(TEXFILENAME).tex

clean:
	rm -f $(TEXFILENAME).aux $(TEXFILENAME).pdf $(TEXFILENAME).bbl $(TEXFILENAME).log $(TEXFILENAME).blg
