dev_dir := $(dir $(lastword $(MAKEFILE_LIST)))
uname_s := $(shell uname -s)

cflags = -std=c99 -Wall -Wpointer-arith \
         -Wsign-compare -Wno-unused-result -Wno-unused-function \
         -funroll-loops -fPIC -pipe \
         -D_GNU_SOURCE -D_POSIX_SOURCE \
         -D_BSD_SOURCE -D_DARWIN_C_SOURCE \
	 -D_REENTRANT -DOPEN_PRINT \
         -I$(dev_dir)src/

libs = -L$(dev_dir)src \
       -lcsnet -lpthread -ldl

ifeq ($(uname_s), Darwin)
  cc = clang
  cflags += -O2 -g -fno-omit-frame-pointer \
            -I/usr/local/Cellar/openssl/1.0.2r/include
  libs += -L/usr/local/Cellar/openssl/1.0.2r/lib
else
  cc = gcc
  cflags += -I/usr/local/include
  libs += -L/usr/local/lib
endif

BUILD_TYPE :=

ifeq ($(BUILD_TYPE), DEBUG)
  cflags += -fsanitize=address -g3 -O0
ifeq ($(uname_s), Linux)
  libs += -lasan
endif
endif

