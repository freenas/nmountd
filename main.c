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

int
main(int ac, char **av)
{
	char *exp_file = "/etc/exports";
	char *line;
	int c;

	while ((c = getopt(ac, av, "dv")) != -1) {
		switch (c) {
		case 'd':	debug++; break;
		case 'v':	verbose++; break;
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
	return 0;
}
