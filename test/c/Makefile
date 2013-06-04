CFLAGS = 
LIBS_PATH := -Lobj/lib
INC_PATH := -Iobj/include -Inss/mozilla/dist/public/nss
LIBS := -lnss3

# This section used to check for existence of a built NSS.
OBJ_PATH_EXISTS := $(shell ls obj)
ifeq "$(OBJ_PATH_EXISTS)" ""
	FAIL_ON_OBJ_DIR = @echo "directory does not exist: $(OBJ_DIR)"; return 1;
endif


.PHONY: all
all: test

# You must have a local build of NSS for this makefile and code to use.
# Create a soft-link to the nss directory from ./nss
# Create a soft-link to nss' object directory from ./obj
# For example, after building nss version 3.14.1 on linux:
#     $ ln -s absolute-path/to/my/nss-dir nss
#     $ ln -s absolute-path/to/my/nss-obj-dir obj
.PHONY: check_obj_dir
check_obj_dir:
	$(FAIL_ON_OBJ_DIR)

#TODO: move individual c files under test
encrypt: encrypt.c
	gcc $(INC_PATH) encrypt.c -o encrypt $(LIBS_PATH) $(LIBS)

hash: hash.c
	g++ $(INC_PATH) hash.c -o hash $(LIBS_PATH) $(LIBS)

hash_etc: hash_etc.c
	g++ $(INC_PATH) hash_etc.c -o hash_etc $(LIBS_PATH) $(LIBS)

key_gen_and_wrap: key_gen_and_wrap.c
	g++ $(INC_PATH) key_gen_and_wrap.c -o key_gen_and_wrap $(LIBS_PATH) $(LIBS)

test: test.c hash.c hash.h
	g++ $(INC_PATH) test.c hash.c -o test $(LIBS_PATH) $(LIBS)

clean: 
	rm -rf *.o encrypt hash hash_etc key_gen_and_wrap
