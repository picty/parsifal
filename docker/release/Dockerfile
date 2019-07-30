FROM pictyeye/parsifal-test:buster

COPY parsifal.tar /tmp/parsifal.tar
RUN cd /tmp/ && \
	tar xf parsifal.tar && \
	cd parsifal && \
	make && \
	LIBDIR=/usr/lib/ocaml make install && \
	rm -rf /tmp/parsifal /tmp/parsifal.tar
