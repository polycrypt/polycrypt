# PolyCrypt crypto tests

This directory contains testing support for the cryptographic functions in polycrypt.  Currently, we test across 3 languages:

* Python (with PyCrypto)
* JavaScript (with a variety of libraries)
* C (with NSS)

The idea is that python can be used as a reference library and design pattern, while the other two platforms can be used for implementing the WebCrypto interface as polyfill or browser code.  C/NSS functions are not currently implemented.

## Structure of this directory

* ./py/ - Files for testing python-based crypto 
* ./js/ - Files for testing JavaScript-based crypto 
* ./js/lib/ - soft link to Libraries used underneath PolyCrypt
* ./js/src/ - soft link to PolyCrypt crypto library implementation
* ./c/ - Files for testing C-based crypto (stub)
* Makefile - Simple running of tests across languages
* TestVectors.in - A file used to generate test vectors for all languages.  Includes references to relevant sources.


## Quickstart

* Dependencies  
    * [PyCrypto][pycrypto]
    * [Rhino JS][rhino]
* Edit ./Makefile to indicate where you put Rhino's js.jar
* make

  [pycrypto]: https://www.dlitz.net/software/pycrypto/
  [rhino]: https://developer.mozilla.org/en-US/docs/Rhino


