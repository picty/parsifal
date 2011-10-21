all: all.otarget

clean: ocamlbuild -clean
tests: tests.otarget

%.otarget: %.itarget
	ocamlbuild $@
