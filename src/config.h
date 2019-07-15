#pragma once

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

int config_load_file(const char *configfile, struct cfgopts config_options[]);
void config_load_defaults(struct cfgopts config_options[]);

