LIBDIRS=syntax core crypto net ssl formats kerby openpgp
DIRS=ssl-tools pci openpgp-tools tools
CHECK_DIRS=syntax/unit core/test core/unit crypto/test net/test formats/test ssl/test

all: libs
	for i in $(DIRS); do OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C $$i all || exit 1; done

libs:
	for i in $(LIBDIRS); do OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C $$i all byte || exit 1; done

byte: libs-byte
	for i in $(DIRS); do OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C $$i byte || exit 1; done

libs-byte:
	for i in $(LIBDIRS); do OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C $$i byte || exit 1; done


install: all
	for i in $(LIBDIRS) $(DIRS); do OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C $$i install || exit 1; done

check: all
	for i in $(CHECK_DIRS); do OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C $$i check || exit 1; done

clean:
	for i in $(DIRS) $(LIBDIRS) $(CHECK_DIRS); do OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C $$i clean || exit 1; done
