#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <err.h>
#include <syslog.h>
#include <signal.h>

#include "mountd.h"
#include "pathnames.h"

int debug = 0;
int verbose = 0;
static sig_atomic_t got_sighup;

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

static void
huphandler(int signo)
{
	got_sighup = 1;
}

static void
terminate(int signo)
{
	stop_rpc();
	exit(0);
}

static void
add_bind_addr(const char *ip)
{
	char **tarray;

	/*
	 * Don't bother with redundant localhosts after the first one.
	 */
	if (server_config.bind_addrs &&
	    (strcmp(ip, "*") == 0 ||
	     strcmp(ip, "127.0.0.1") == 0 ||
	     strcmp(ip, "::1") == 0 ||
	     strcmp(ip, "localhost") == 0)) {
		return;
	}
	tarray = realloc(server_config.bind_addrs, sizeof(char**) * (server_config.naddrs + 1));
	if (tarray == NULL) {
		out_of_mem();
	}
	server_config.bind_addrs = tarray;
	server_config.bind_addrs[server_config.naddrs++] = strdup(ip);
	return;
}


static void
load_exports(char **files, size_t count)
{
	size_t indx;
	
	for (indx = 0; indx < count; indx++) {
		char *exp_file = files[indx];
		FILE *fp = fopen(exp_file, "r");
		if (fp == NULL) {
			warn("Could not open %s", exp_file);
		}
		read_export_file(fp);
		fclose(fp);
	}
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


	load_exports(export_files, ef_count);
	
	if (verbose) {
		if (debug)
			PrintTree();
		else
			ListExports();
	}

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

	signal(SIGHUP, huphandler);
	signal(SIGTERM, terminate);
	signal(SIGPIPE, SIG_IGN);
	// Need to ignore SIGINT and SIGQUIT
	
	// Does this need to re-happen on SIGHUP?
	init_rpc();

	UnexportFilesystems();
	ExportFilesystems();

	while (1) {
		if (got_sighup) {
			got_sighup = 0;
			load_exports(export_files, ef_count);
			UnexportFilesystems();
			ExportFilesystems();
		}
		service_rpc();
	}
		UnexportFilesystems();
	return 0;
}

void
out_of_mem(void)
{
	syslog(LOG_ERR, "out of memory");
	exit(2);
}
