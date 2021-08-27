#ifndef cfg_h
#define cfg_h

struct defval {
	int int4;
	char *string;
};

struct cfgopts {
	char *keyword;
	enum type { TYP_INT4, TYP_STRING } type;
	void *dest;
	struct defval defval;
};

int cfg_load_file(const char *configfile, struct cfgopts config_options[]);
void cfg_load_defaults(struct cfgopts config_options[]);

#endif  /* cfg_h */

