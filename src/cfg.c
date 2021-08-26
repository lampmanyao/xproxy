#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include "cfg.h"
#include "utils.h"
#include "log.h"

void cfg_load_defaults(struct cfgopts config_options[])
{
	int i;
	void *ptr;

	for (i = 0; config_options[i].keyword; i++) {
		switch (config_options[i].type) {
		case TYP_INT4:
			ptr = config_options[i].dest;
			*(int *)ptr = config_options[i].defval.int4;
			break;

		case TYP_STRING:
			ptr = config_options[i].dest;
			memcpy(ptr, &config_options[i].defval.string, sizeof(char *));
			break;

		default:
			break;
		}
	}
}

int cfg_load_file(const char *configfile, struct cfgopts config_options[])
{
	char buff[1024];
	char *ptr;
	unsigned long i;
	int k;
	int num;
	size_t len;
	char *tmpptr;
	char *eqsign;

	FILE *f = fopen(configfile, "r");
	if (!f)
		return -1;

	while (fgets(buff, sizeof(buff), f) != NULL) {
		buff[sizeof(buff) - 1] = '\0';

		for (i = 1; i < 2; i++) {
			if (buff[strlen(buff) - i] == '\n' ||
			    buff[strlen(buff) - i] == '\r') {
				buff[strlen(buff) - i] = '\0';
			}
		}

		if (buff[0] == '\0')
			continue;

		for (i = 0; i < strlen(buff); i++) {
			if (buff[i] == ' ' || buff[i] == '\t')
				continue;

			if (buff[i] == '#')
				i = strlen(buff);

			break;
		}

		if (i == strlen(buff))
			continue;

		eqsign = strchr(buff, '=');

		if (!eqsign)
			continue;

		for (k = 0; config_options[k].keyword; k++) {
			if ((ptr = strstr(buff, config_options[k].keyword))) {
				ptr += strlen(config_options[k].keyword);

				if (*ptr != ' ' && *ptr != '\t' && *ptr != '=')
					break;

				if (!(ptr = strchr(ptr, '=')))
					break;

				do {
					ptr++;
				} while (*ptr == ' ' || *ptr == '\t');

				num = 0;

				if (strlen(ptr) == 0)
					break;

				switch (config_options[k].type) {
				case TYP_INT4:
					num = sscanf(ptr, "%i", (int*)config_options[k].dest);
					break;

				case TYP_STRING:
					len = strlen(ptr) + 1;
					tmpptr = malloc(len);
					memcpy(config_options[k].dest, &tmpptr, sizeof(tmpptr));
					num = sscanf(ptr, "%[^#]", tmpptr);
					tmpptr[len - 1] = '\0';
					i = strlen(tmpptr);
					do { i--; } while (i > 0 && tmpptr[i] == ' ');
					tmpptr[i + 1] = '\0';
					break;

				default:
					break;
				}
			}
		}
	}

	fclose(f);
	return 0;
}

