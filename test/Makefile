RHINO_HOME = ../../tool
JS_SRC = ../src

all: py js c
	echo "done"

py: testvectors py/*
	python py/test.py

js: testvectors js/*
	cp -R ${JS_SRC}/back/lib js/
	mkdir js/src
	cp ${JS_SRC}/back/libpolycrypt.js js/src/.
	cp ${JS_SRC}/common/util.js js/src/.
	cd js && java -jar ${RHINO_HOME}/js.jar test.js	

c: testvectors c/*
	gcc c/test.c -o c/test
	./c/test

testvectors: TestVectors.in
	# Python
	cat TestVectors.in | grep "=" | grep -v "#" | sed -e 's/"$$/".decode("hex")/' >py/TestVectors.py

	# JS
	echo "tv = {};" >js/TestVectors.js
	cat TestVectors.in | grep "=" | grep -v "#" \
        | sed -e 's/^/tv./; s/= "/= util.hex2abv("/; s/\([^"]\)$$/\1;/; s/"$$/");/' >>js/TestVectors.js
	
	# HTML / API (must be run manually)
	cp js/TestVectors.js ../src/app/api-test/.
	cp js/TestVectors.js ../src/app/demo/.

	# C
	cat TestVectors.in | grep "=" | grep -v "#" | sed -e 's/^/const char\* /; s/$$/;/' \
		| sed -e 's/^const char\* \([^"]*\)$$/int \1/' >c/TestVectors.h

clean:
	rm -f py/TestVectors.py py/*.pyc js/TestVectors.js c/TestVectors.h c/test
	rm -rf js/lib js/src
	rm -f ../src/app/api-test/TestVectors.js
