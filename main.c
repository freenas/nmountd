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
static char *default_export = _PATH_EXPORTS;
static char **default_exports = &default_export;

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

static void
add_bind_addr(const char *ip)
{
	char **tarray;

	if (strcmp(ip, "*") == 0 ||
	    strcmp(ip, "127.0.0.1") == 0 ||
	    strcmp(ip, "::1") == 0 ||
	    strcmp(ip, "localhost") == 0) {
		// All forms of localhost
		return;
	}
	tarray = realloc(server_config.bind_addrs, sizeof(char**) * (server_config.naddrs + 1));
	if (tarray == NULL) {
		out_of_mem();
	}
	server_config.bind_addrs = tarray;
	// This isn't quite right, need to make sure it's a valid host/address
	server_config.bind_addrs[server_config.naddrs++] = strdup(ip);
	return;
}

int
main(int ac, char **av)
{
	int c;
	struct Find *findit = NULL;
	char **export_files = NULL;
	size_t ef_count = 0;
	size_t indx;
	
	
	add_bind_addr("*");
	
	while ((c = getopt(ac, av, "2nrdvlF:h:")) != -1) {
		switch (c) {
		case '2':	server_config.force_v2 = 1; break;
		case 'n':	server_config.resvport_only = 0; break;
		case 'r':	server_config.dir_only = 0; break;
		case 'l':	server_config.dolog = 1; break;
		case 'd':	debug++; break;
		case 'v':	verbose++; break;
		case 'F':	findit = Find(optarg); break;
		case 'h':	add_bind_addr(optarg); break;
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
		char *exp_file = export_files[indx];
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
