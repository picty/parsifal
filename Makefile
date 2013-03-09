all:
	$(MAKE) -C syntax install
	$(MAKE) -C core install
	$(MAKE) -C core/test check
	$(MAKE) -C ssl install
	$(MAKE) -C ssl/test check

clean:
	$(MAKE) -C syntax clean
	$(MAKE) -C core clean
	$(MAKE) -C core/test clean
	$(MAKE) -C ssl clean
	$(MAKE) -C ssl/test clean
