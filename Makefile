all:
	$(MAKE) -C syntax all byte
	OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C core all byte
	[ -z "${DO_UNIT_TEST}" ] || OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C core/unit check
	OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C core/test check
	OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C net all byte
	OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C net/test check
	OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C formats all byte
	OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C formats/test check
	OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C ssl all byte
	OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C ssl/test check
	OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C kerby all byte
	OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C net-tools all
	OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C ssl-tools all
	OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C tools all

install::
	$(MAKE) -C syntax install
	$(MAKE) -C core install
	$(MAKE) -C core/test install
	$(MAKE) -C net install
	$(MAKE) -C net/test install
	$(MAKE) -C formats install
	$(MAKE) -C formats/test install
	$(MAKE) -C ssl install
	$(MAKE) -C ssl/test install
	$(MAKE) -C net-tools install
	$(MAKE) -C ssl-tools install
	$(MAKE) -C tools install

clean:
	OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C tools clean
	OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C ssl-tools clean
	OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C net-tools clean
	OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C kerby clean
	OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C ssl/test clean
	OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C ssl clean
	OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C formats/test clean
	OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C formats clean
	OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C net/test clean
	OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C net clean
	OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C core/test clean
	OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C core/unit clean
	OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C core clean
	$(MAKE) -C syntax clean
