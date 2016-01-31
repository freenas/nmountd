#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <err.h>
#include <syslog.h>

#include "mountd.h"
#include "pathnames.h"

int debug = 0;
int verbose = 0;
struct server_config server_config = {
	.resvport_only = 1,
	.dir_only = 1,
	.have_v6 = 0,
};

static void
usage(const char *progname)
{
	fprintf(stderr, "Usage: %s [-dv] [export_file [...]]\n", progname);
	exit(1);
}

struct Find {
	struct sockaddr *addr;
	char *path;
};

#include <netdb.h>

static struct Find *
Find(const char *arg)
{
	struct Find *retval = NULL;
	char *s = strdup(arg);
	char *path, *addr = s;
	struct addrinfo *ai;
	
	path = strsep(&addr, ";");

	printf("path = %s, addr = %s\n", path, addr);
	retval = calloc(1, sizeof(*retval));
	retval->path = strdup(path);
	
	if (getaddrinfo(addr, NULL, NULL, &ai) != 0) {
		abort();
	} else {
		retval->addr = ai->ai_addr;
	}
	free(s);
	return retval;
}

extern void init_rpc(void);

int
main(int ac, char **av)
{
	char *exp_file = "/etc/exports";
	char *line;
	int c;
	struct Find *findit = NULL;
	char **export_files = NULL;
	size_t ef_count = 0;
	size_t indx;
	static char *default_export = _PATH_EXPORTS;
	static char **default_exports = &default_export;
	
	
	while ((c = getopt(ac, av, "2nrdvlF:")) != -1) {
		switch (c) {
		case '2':	server_config.force_v2 = 1; break;
		case 'n':	server_config.resvport_only = 0; break;
		case 'r':	server_config.dir_only = 0; break;
		case 'l':	server_config.dolog = 1; break;
		case 'd':	debug++; break;
		case 'v':	verbose++; break;
		case 'F':	findit = Find(optarg); break;
		default:	usage(av[0]);
		}
	}

	if (check_ipv6() != 0)
		server_config.have_v6 = 1;
	
	av += optind;
	ac -= optind;

	if (ac == 0) {
		export_files = default_exports;
		ef_count = 1;

	} else {
		export_files = av;
		ef_count = ac;
	}

	UnexportFilesystems();
	for (indx = 0; indx < ef_count; indx++) {
		exp_file = export_files[indx];
		FILE *fp = fopen(exp_file, "r");
		if (fp == NULL) {
			warn("Could not open %s", exp_file);
		}
		read_export_file(fp);
		fclose(fp);
	}
	
	if (verbose)
		PrintTree();

	if (findit) {
		struct export_entry *ep;
		char *export_name;
		
		ep = FindBestExportForAddress(findit->path, findit->addr, &export_name);
		if (ep)
			printf("export_name = %s, real path = %s\n", export_name, ep->export_path);
		else
			printf("Could not find appropriate export\n");
		ReleaseTree();
		return 0;
	}
	ExportFilesystems();
	init_rpc();
	UnexportFilesystems();
	return 0;
}

void
out_of_mem(void)
{
	syslog(LOG_ERR, "out of memory");
	exit(2);
}
