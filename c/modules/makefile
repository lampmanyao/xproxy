subdirs = local-btgfw-module remote-btgfw-module
 
target:
	for dir in $(subdirs); do \
		$(MAKE) -C $$dir; \
	done
 
clean:
	for dir in $(subdirs); do \
		$(MAKE) -C $$dir clean; \
	done

