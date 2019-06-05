#include "libcsnet.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/resource.h>

int main(int argc, char** argv)
{
	if (argc != 2) {
		fatal("usage: %s config", argv[0]);
	}

	csnet_signals_init();
	csnet_coredump_init();

	char* conf_file = argv[1];
	int log_size;
	int log_level;
	int max_files;
	char* logfile;
	char* logsize;
	char* loglevel;
	char* maxfiles;
	char* myport;
	char* remote_host;
	char* remote_port;
	char* maxconn;
	char* threadcount;
	char* business_module;

	struct csnet* csnet;
	struct csnet_log* logger;
	struct csnet_config* config;
	struct csnet_module* module;
	struct csnet_conntor* conntor;

	csnet_crypt_setup();
	config = csnet_config_new();
	csnet_config_load(config, conf_file);

	logfile = csnet_config_find(config, "logfile", strlen("logfile"));
	logsize = csnet_config_find(config, "logsize", strlen("logsize"));
	loglevel = csnet_config_find(config, "loglevel", strlen("loglevel"));
	maxfiles = csnet_config_find(config, "maxfiles", strlen("maxfiles"));

	if (!logfile) {
		debug("can not find `logfile` is %s, use %s as logfile name",
			conf_file, argv[0]);
		logfile = argv[0];
	}

	if (!logsize) {
		debug("can not find `logsize` in %s, use default size: %d Mb",
		      conf_file, LOGGER_DEFAULT_FILE_SIZE);
		log_size = LOGGER_DEFAULT_FILE_SIZE * 1024 * 1024;
	} else {
		log_size = atoi(logsize) * 1024 * 1024;
	}

	if (!loglevel) {
		debug("cant not find `loglevel` in %s, use default level: DEBUG", conf_file);
		log_level = LOGGER_DEFAULT_LEVEL;
	} else {
		log_level = atoi(loglevel);
	}

	if (!maxfiles) {
		debug("can not find `maxfiles` in %s, use default maxfiles: 1024", conf_file);
		max_files = 1024;
	} else {
		max_files = atoi(maxfiles);
	}

	if (csnet_openfiles_init(max_files) != 0) {
		fatal("set max open files to %d failed: %s", max_files, strerror(errno));
	}

	logger = csnet_log_new(logfile, log_level, log_size);
 	if (!logger) {
		 fatal("can not open logfile\n");
	}

	myport = csnet_config_find(config, "myport", strlen("myport"));
	remote_host = csnet_config_find(config, "remote_host", strlen("remote_host"));
	remote_port = csnet_config_find(config, "remote_port", strlen("remote_port"));
	maxconn = csnet_config_find(config, "maxconn", strlen("maxconn"));
	threadcount = csnet_config_find(config, "threadcount", strlen("threadcount"));
	business_module = csnet_config_find(config, "business-module", strlen("business-module"));

	if (!myport) {
		log_f(logger, "could not find `myport`!");
	}
	if (!remote_host) {
		log_f(logger, "could not find `remote_host`!");
	}
	if (!remote_port) {
		log_f(logger, "could not find `remote_port`!");
	}

	if (!maxconn) {
		log_f(logger, "could not find `maxconn`!");
	}

	if (!threadcount) {
		log_f(logger, "could not find `threadcount`!");
	}

	if (!business_module) {
		log_f(logger, "could not find `business-module`!");
	}

	module = csnet_module_new();
	conntor = csnet_conntor_new(config, logger, module);
	csnet_module_init(module, conntor, logger, config);
	csnet_module_load(module, business_module);
	csnet = csnet_new(atoi(myport), atoi(threadcount), atoi(maxconn), logger, module);

	log_i(logger, "Server start ok ...");

	csnet_conntor_loop(conntor);
	csnet_loop(csnet, -1);

	csnet_free(csnet);
	csnet_config_free(config);
	csnet_module_free(module);
	csnet_conntor_free(conntor);
	csnet_log_free(logger);

        return 0;
}

