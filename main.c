#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <err.h>

#include "mountd.h"

int debug = 0;
int verbose = 0;

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

int
main(int ac, char **av)
{
	char *exp_file = "/etc/exports";
	char *line;
	int c;
	struct Find *findit = NULL;
	
	while ((c = getopt(ac, av, "dvF:")) != -1) {
		switch (c) {
		case 'd':	debug++; break;
		case 'v':	verbose++; break;
		case 'F':	findit = Find(optarg); break;
		default:	usage(av[0]);
		}
	}
	av += optind;
	ac -= optind;

	if (ac == 0) {
		exp_file = "/etc/exports";
		ac = 1;	// hack
	} else {
		exp_file = *av++;
	}

	if (ac > 0) {
		UnexportFilesystems();
	}
	do {
		FILE *fp = fopen(exp_file, "r");
		if (fp == NULL) {
			warn("Could not open %s", exp_file);
		}
		read_export_file(fp);
		fclose(fp);
		ac--, av++;
	} while (ac != 0);
	
	if (verbose)
		PrintTree();

	if (findit) {
		struct export_entry *ep;
		char *export_name;
		
		ep = FindBestExportForAddress(findit->path, findit->addr, &export_name);
		if (ep)
			printf("export_name = %s, real path = %s\n", export_name, ep->export_path);
		else
			printf("Could not find appropriate export");
	}
	ExportFilesystems();
	UnexportFilesystems();
	return 0;
}
