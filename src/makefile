uname_s := $(shell uname -s)

cflags = -std=c99 -Wall -Wpointer-arith -fno-omit-frame-pointer \
         -Wsign-compare -Wno-unused-result -Wno-unused-function \
	 -Wextra -Wshadow -Wconversion \
         -funroll-loops -fPIC -pipe \
         -D_GNU_SOURCE -D_POSIX_SOURCE \
         -D_BSD_SOURCE -D_DARWIN_C_SOURCE \
	 -D_REENTRANT -DOPEN_PRINT \
         -I./

libs = -lpthread -ldl -lssl -lcrypto

ifeq ($(uname_s), Darwin)
  cc = clang
  cflags += -I/usr/local/Cellar/openssl/1.0.2s/include
  libs += -L/usr/local/Cellar/openssl/1.0.2s/lib
else
  cc = gcc
  cflags += -I/usr/local/include
  libs += -L/usr/local/lib
endif

BUILD_TYPE :=

ifeq ($(BUILD_TYPE), DEBUG)
  cflags += -fsanitize=address -ggdb -O0
  ifeq ($(uname_s), Linux)
    libs += -lasan
  endif
else
  cflags += -O2
endif

srcs = btgfw.c el.c config.c tcp-connection.c crypt.c utils.c rbtree.c

objs = $(srcs:.c=.o)

target = $(objs) local-btgfw remote-btgfw

all: $(target)

%.o: %.c
	$(cc) $(cflags) -c $< -o $@

local-btgfw: local-btgfw.o $(objs)
	$(cc) $(cflags) $^ -o $@ $(libs)

local-btgfw.o: local-btgfw.c
	$(cc) $(cflags) -c $< -o $@

remote-btgfw: remote-btgfw.o $(objs)
	$(cc) $(cflags) $^ -o $@ $(libs)

remote-btgfw.o: remote-btgfw.c
	$(cc) $(cflags) -c $< -o $@

.PHONY: clean
clean:
	rm -rf $(objdir)
	rm -f $(target) *.o

