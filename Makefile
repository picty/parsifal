all:
	$(MAKE) -C syntax install
	$(MAKE) -C core install
	$(MAKE) -C core/test check
	$(MAKE) -C net install
	$(MAKE) -C net/test check
	$(MAKE) -C ssl install
	$(MAKE) -C ssl/test check

clean:
	$(MAKE) -C syntax clean
	$(MAKE) -C core clean
	$(MAKE) -C core/test clean
	$(MAKE) -C net clean
	$(MAKE) -C net/test clean
	$(MAKE) -C ssl clean
	$(MAKE) -C ssl/test clean
