all: html/index.html

html/index.html: ../mspack/mspack.h Doxyfile szdd_kwaj_format.html
	doxygen
	cp szdd_kwaj_format.html html/

clean:
	rm -rf html
