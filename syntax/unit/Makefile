OCAMLFIND = ocamlfind
CAMLP4 = camlp4o
BUILD_DIR = build

INCLUDES = $(shell $(OCAMLFIND) query -format "-I %d" -predicates syntax parsifal_syntax)


check:	enum-01.test enum-02.test enum-03.test enum-04.test enum-05.test


$(BUILD_DIR):
	@[ -d "$(BUILD_DIR)" ] || mkdir $(BUILD_DIR)

$(BUILD_DIR)/%.ast: %.ml build
	@if $(CAMLP4) $(INCLUDES) parsifal_syntax.cma -o $@ $< 2> $(BUILD_DIR)/$*.err; \
	then rm -f $(BUILD_DIR)/$*.err; \
	else mv $(BUILD_DIR)/$*.err $(BUILD_DIR)/$*.ast; \
	fi

$(BUILD_DIR)/%.diff: $(BUILD_DIR)/%.ast %.out
	@diff $< $*.out > $@

%.test:	$(BUILD_DIR)/%.diff
	@echo $* OK


clean:
	[ -z "$(BUILD_DIR)" ] || rm -rf $(BUILD_DIR)
