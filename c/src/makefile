include ../csnet.mk

install_dir = /usr/local/libcsnet
srcs = $(wildcard *.c)
cobjs = $(srcs:.c=.o)
objdir = .objs
objs = $(addprefix $(objdir)/, $(cobjs))

$(objdir):
	@mkdir -p $@

target = libcsnet.a

all: $(target)

$(target): $(objs)
	ar rc $@ $^

$(objdir)/%.o: %.c | $(objdir)
	$(cc) $(cflags) -c $< -o $@

install:
	@mkdir -p $(install_dir)
	@cp *.h $(install_dir)
	@cp ../libcsnet.mk $(install_dir)
	@cp $(target) $(install_dir)

uninstall:
	@rm $(install_dir)/*.h
	@rm $(install_dir)/libcsnet.mk
	@rm $(install_dir)/$(target)
	@rmdir $(install_dir)

.PHONY: clean
clean:
	rm -rf $(objdir)
	rm -f $(target)

