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

int config_init(const char *configfile, struct cfgopts config_options[]);
