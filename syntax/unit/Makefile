OCAMLFIND = ocamlfind
CAMLP4 = camlp4o
BUILD_DIR = build

INCLUDES = $(shell $(OCAMLFIND) query -format "-I %d" -predicates syntax parsifal_syntax)

.PRECIOUS: $(BUILD_DIR)/%.ast $(BUILD_DIR)/%.diff


check:	enum-01.test enum-02.test enum-03.test enum-04.test \
	enum-05.test enum-06.test enum-07.test enum-08.test \
	enum-09.test enum-0a.test enum-0b.test enum-0c.test \
	enum-0d.test enum-0e.test enum-0f.test enum-10.test \
	enum-11.test enum-12.test enum-13.test enum-14.test \
	enum-15.test enum-16.test enum-17.test \
	struct-01.test struct-02.test struct-03.test struct-04.test \
	struct-05.test struct-06.test struct-07.test struct-08.test \
	struct-09.test struct-0a.test struct-0b.test struct-0c.test \
	struct-0d.test struct-0e.test struct-0f.test struct-10.test \
	struct-11.test struct-12.test struct-13.test struct-14.test \
	struct-15.test struct-16.test

$(BUILD_DIR):
	@[ -d "$(BUILD_DIR)" ] || mkdir $(BUILD_DIR)

$(BUILD_DIR)/%.ast: %.ml build
	@if $(CAMLP4) $(INCLUDES) -printer Camlp4OCamlPrinter parsifal_syntax.cma -o $@ $< 2> $(BUILD_DIR)/$*.err; \
	then rm -f $(BUILD_DIR)/$*.err; \
	else mv $(BUILD_DIR)/$*.err $(BUILD_DIR)/$*.ast; \
	fi

$(BUILD_DIR)/%.diff: $(BUILD_DIR)/%.ast %.out
	@diff $< $*.out > $@

%.test:	$(BUILD_DIR)/%.diff
	@echo $* OK


clean:
	[ -z "$(BUILD_DIR)" ] || rm -rf $(BUILD_DIR)
