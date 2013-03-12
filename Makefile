all:
	$(MAKE) -C syntax
	OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C core all byte
	OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C core/test all byte check
	OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C net all byte
	OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C net/test all byte check
	OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C formats all byte
	OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C formats/test all byte check
	OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C ssl all byte
	OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C ssl/test all byte check
	OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C ssl-tools all byte

clean:
	OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C ssl-tools clean
	OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C ssl/test clean
	OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C ssl clean
	OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C formats/test clean
	OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C formats clean
	OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C net/test clean
	OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C net clean
	OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C core/test clean
	OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C core clean
	$(MAKE) -C syntax clean
