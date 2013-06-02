LIBDIRS=syntax core net formats ssl kerby
DIRS=net-tools ssl-tools tools pci
CHECK_DIRS=core/test core/unit net/test formats/test ssl/test

all: libs
	for i in $(DIRS); do OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C $$i all || exit 1; done

libs:
	for i in $(LIBDIRS); do OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C $$i all byte || exit 1; done

install: all
	for i in $(LIBDIRS) $(DIRS); do OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C $$i install || exit 1; done

check: all
	for i in $(CHECK_DIRS); do OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C $$i check || exit 1; done

clean:
	for i in $(DIRS) $(LIBDIRS); do OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C $$i clean || exit 1; done
