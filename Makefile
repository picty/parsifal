all:
	$(MAKE) -C syntax
	OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C core all byte
	OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C core/test all byte check
	OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C net all byte
	OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C net/test all byte check
	OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C ssl all byte
	OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C ssl/test all byte check
	OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C tools all byte

clean:
	OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C tools clean
	OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C ssl/test clean
	OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C ssl clean
	OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C net/test clean
	OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C net clean
	OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C core/test clean
	OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C core clean
	OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C syntax clean
