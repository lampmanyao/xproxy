include ../../csnet.mk

#ifeq ($(uname_s), Darwin)
  libs += -lssl -lcrypto
#endif

cflags += -I$(dev_dir)business/include

obj_dir = .objs
local_srcs = $(wildcard *.c)
local_objs = $(local_srcs:.c=.o)
objs = $(addprefix $(obj_dir)/, $(local_objs))

$(obj_dir):
	@mkdir -p $@

target = business-module.so

all: $(target)

$(target): $(objs)
	$(cc) $(cflags) -shared -nostartfiles -o $@ $(objs) $(libs)

$(obj_dir)/%.o: %.c | $(obj_dir)
	$(cc) $(cflags) -c $< -o $@

install:
	cp business-module.so ../../remote-btgfw

.PHONY: clean
clean:
	rm -rf $(obj_dir)
	rm -f $(target)
