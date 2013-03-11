all:
	$(MAKE) -C syntax
	OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C core all byte
	OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C core/test check
	OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C net all byte
	OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C net/test check
	OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C ssl all byte
	OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C ssl/test check

clean:
	OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C ssl/test clean
	OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C ssl clean
	OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C net/test clean
	OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C net clean
	OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C core/test clean
	OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C core clean
	OCAMLPATH="$(PWD)/usrlibocaml" $(MAKE) -C syntax clean
