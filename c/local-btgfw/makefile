include ../csnet.mk
ifeq ($(uname_s), Linux)
cflags += -rdynamic
endif

libs += -lssl -lcrypto

obj_dir = .objs
local_srcs = $(wildcard *.c)
local_objs = $(local_srcs:.c=.o)
objs = $(addprefix $(obj_dir)/, $(local_objs))

$(obj_dir):
	@mkdir -p $@

target = local-btgfw

all: $(target)

$(target): $(objs)
	$(cc) $(cflags) -o $@ $(objs) $(libs)

$(obj_dir)/%.o: %.c | $(obj_dir)
	$(cc) $(cflags) -c $< -o $@

.PHONY: clean
clean:
	rm -rf $(obj_dir)
	rm -f $(target)
	rm -f *.log nohup.out *.pid
