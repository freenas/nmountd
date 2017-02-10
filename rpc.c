/*
 * Copyright (c) 2016, iXsystems, Inc.
 * Copyright (c) 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Herb Hasler and Rick Macklem at The University of Guelph.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef lint
static const char copyright[] =
"@(#) Copyright (c) 1989, 1993\n\
	The Regents of the University of California.  All rights reserved.\n";
#endif /*not lint*/

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>

#include <sys/param.h>
#include <sys/fcntl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syslog.h>
#include <sys/socket.h>
#include <sys/sysctl.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <rpc/rpc.h>
#include <rpc/rpc_com.h>
#include <rpc/pmap_clnt.h>
#include <rpc/pmap_prot.h>
#include <rpcsvc/mount.h>
#include <nfs/nfsproto.h>
#include <nfs/nfssvc.h>
#include <nfsserver/nfs.h>

#include <fs/nfs/nfsport.h>

#include "mountd.h"

char *svcport_str;
int *sock_fd;
size_t sock_fdcnt;
int mallocd_svcport;
int sock_fdpos;
size_t xcreated;

struct fhreturn {
	int	fhr_flag;
	int	fhr_vers;
	nfsfh_t	fhr_fh;
	int	fhr_numsecflavors;
	int	*fhr_secflavors;
};

/*
 * Structure for keeping the mount list
 */

struct mountlist {
	struct mountlist *ml_next;
	char	ml_host[MNTNAMLEN+1];
	char	ml_exp[MNTNAMLEN+1];
	char	ml_real[MNTPATHLEN+1];
};
/*
 * I have no idea what to do for this.
 */
static int resvport_only;

/*
 * This is a list of filesystems that are mounted
 * (as far as we know, anyway).
 */
static struct mountlist *current_mounts;

static void
add_mount(char *exp, char *real, char *hostp)
{
	struct mountlist *mlp, **mlpp;
	FILE *mlfile;

	mlpp = &current_mounts;
	mlp = current_mounts;
	while (mlp) {
		if (!strcmp(mlp->ml_host, hostp) && !strcmp(mlp->ml_exp, exp))
			return;
		mlpp = &mlp->ml_next;
		mlp = mlp->ml_next;
	}
	mlp = (struct mountlist *)malloc(sizeof (*mlp));
	if (mlp == (struct mountlist *)NULL)
		out_of_mem();
	strlcpy(mlp->ml_host, hostp, MNTNAMLEN+1);
	strlcpy(mlp->ml_exp, exp, MNTPATHLEN);
	strlcpy(mlp->ml_real, real, MNTPATHLEN+1);
	mlp->ml_next = (struct mountlist *)NULL;
	*mlpp = mlp;
	if ((mlfile = fopen(_PATH_RMOUNTLIST, "a")) == NULL) {
		syslog(LOG_ERR, "can't update %s", _PATH_RMOUNTLIST);
		return;
	}
	fprintf(mlfile, "%s %s %s\n", mlp->ml_host, mlp->ml_exp, mlp->ml_real);
	fclose(mlfile);
}

void
del_mount(char *hostp, char *exp)
{
	struct mountlist *mlp, **mlpp;
	struct mountlist *mlp2;
	FILE *mlfile;
	int fnd = 0;

	mlpp = &current_mounts;
	mlp = current_mounts;;
	while (mlp) {
		if (!strcmp(mlp->ml_host, hostp) &&
		    (!exp || !strcmp(mlp->ml_exp, exp))) {
			fnd = 1;
			mlp2 = mlp;
			*mlpp = mlp = mlp->ml_next;
			free((caddr_t)mlp2);
		} else {
			mlpp = &mlp->ml_next;
			mlp = mlp->ml_next;
		}
	}
	if (fnd) {
		if ((mlfile = fopen(_PATH_RMOUNTLIST, "w")) == NULL) {
			syslog(LOG_ERR,"can't update %s", _PATH_RMOUNTLIST);
			return;
		}
		mlp = current_mounts;
		while (mlp) {
			fprintf(mlfile, "%s %s %s\n", mlp->ml_host, mlp->ml_exp, mlp->ml_real);
			mlp = mlp->ml_next;
		}
		fclose(mlfile);
	}
}

/*
 * Xdr conversion for a dirpath string
 */
static int
xdr_dir(XDR *xdrsp, char *dirp)
{
	return (xdr_string(xdrsp, &dirp, MNTPATHLEN));
}

static int
xdr_explist_common(XDR *xdrsp, caddr_t cp __unused, int brief)
{
	sigset_t sighup_mask;
	int true = 1;
	int false = 0;

	sigemptyset(&sighup_mask);
	sigaddset(&sighup_mask, SIGHUP);
	sigprocmask(SIG_BLOCK, &sighup_mask, NULL);


	/*
	 * protocol seems to be:
	 * <true><mount>[(<true><address>)*]<false>
	 */
	IterateTree(^(struct export_node *ep) {
			char *strp;
			size_t indx;
			int true = 1, false = 0;
			
			// Handle default first
			if (ep->default_export.export_path) {
				struct export_entry *ed = &ep->default_export;
				if (debug)
					fprintf(stderr, "Sending default true\n");
				if (!xdr_bool(xdrsp, &true))
					return (1);
				if (strcmp(ep->export_name, ed->export_path) == 0) {
					strp = strdup(ep->export_name);
				} else {
					asprintf(&strp, "%s=%s", ed->export_path, ep->export_name);
				}
				if (debug) {
					fprintf(stderr, "Sending default export %s\n", strp);
				}
				if (!xdr_string(xdrsp, &strp, strlen(strp) + 1)) {
					free(strp);
					return (1);
				}
				free(strp);
				if (debug)
					fprintf(stderr, "Sending default false\n");
				if (!xdr_bool(xdrsp, &false))
					return (1);
			}
			// Now go through all of the exports
			for (indx = 0; indx < ep->export_count; indx++) {
				struct export_entry *exp = ep->exports[indx];
				size_t network_indx;
				size_t max_len;
				
				if (debug)
					fprintf(stderr, "sending entry true\n");
				if (!xdr_bool(xdrsp, &true))
					return (1);

				if (strcmp(ep->export_name,
					   exp->export_path) == 0) {
					strp = strdup(ep->export_name);
				} else {
					asprintf(&strp, "%s=%s", exp->export_path, ep->export_name);
				}
				max_len = strlen(strp) + 1;
				if (debug)
					fprintf(stderr, "Sending export list entry %s", strp);
				
				if (!xdr_string(xdrsp, &strp, max_len)) {
					free(strp);
					return (1);
				}
				free(strp);
				
				if (brief) {
					if (debug)
						fprintf(stderr, "<true>");
					if (!xdr_bool(xdrsp, &true))
						return (1);
					
					strp = "(...)";
					if (debug)
						fprintf(stderr, " %s", strp);
					if (!xdr_string(xdrsp, &strp, strlen(strp) + 1))
						return (1);
				} else {
					for (network_indx = 0;
					     network_indx < exp->network_count;
					     network_indx++) {
						struct network_entry *np = &exp->entries[network_indx];
						char host[255];
						struct sockaddr *sap = np->network;

						if (debug)
							fprintf(stderr, "<true>");
						if (!xdr_bool(xdrsp, &true))
							return (1);

						if (np->mask == NULL) {
							// A host
							if (getnameinfo(sap, sap->sa_len, host, sizeof(host),
									NULL, 0, 0) != 0) {
								if (getnameinfo(sap, sap->sa_len, host, sizeof(host),
										NULL, 0, NI_NUMERICHOST) != 0)
									strcpy(host, "<unknown>");
							}
							strp = strdup(host);
						} else {
							if (getnameinfo(sap, sap->sa_len, host, sizeof(host),
									NULL, 0, NI_NUMERICHOST) != 0)
								strcpy(host, "<unknown>");
							asprintf(&strp, "%s/%d", host, netmask_to_masklen(np->mask));
						}
						
						if (debug)
							fprintf(stderr, " %s", strp);
						
						if (!xdr_string(xdrsp, &strp, strlen(strp) + 1)) {
							free(strp);
							return (1);
						}
					}
				}
				if (debug)
					fprintf(stderr, "<false>\n");
				if (!xdr_bool(xdrsp, &false))
					return (1);
			}
			return 0;
		});
	
	sigprocmask(SIG_UNBLOCK, &sighup_mask, NULL);
	if (debug)
		fprintf(stderr, "Sending final false\n");
	if (!xdr_bool(xdrsp, &false))
		return (0);
	return 1;
}

static int
xdr_explist(XDR *xdrsp, caddr_t cp)
{
	return xdr_explist_common(xdrsp, cp, 0);
}
static int
xdr_explist_brief(XDR *xdrsp, caddr_t cp)
{
	return xdr_explist_common(xdrsp, cp, 1);
}

static int
xdr_mlist(XDR *xdrsp, caddr_t cp __unused)
{
	struct mountlist *mlp;
	int true = 1;
	int false = 0;
	char *strp;

	mlp = current_mounts;
	while (mlp) {
		if (!xdr_bool(xdrsp, &true))
			return (0);
		strp = &mlp->ml_host[0];
		if (!xdr_string(xdrsp, &strp, MNTNAMLEN))
			return (0);
		strp = &mlp->ml_real[0];
		if (!xdr_string(xdrsp, &strp, MNTPATHLEN))
			return (0);
		mlp = mlp->ml_next;
	}
	if (!xdr_bool(xdrsp, &false))
		return (0);
	return (1);
}
/*
 * Xdr routine to generate file handle reply
 */
static int
xdr_fhs(XDR *xdrsp, caddr_t cp)
{
	struct fhreturn *fhrp = (struct fhreturn *)cp;
	long ok = 0;
	u_long len, auth;
	int i;

	if (!xdr_long(xdrsp, &ok))
		return (0);
	switch (fhrp->fhr_vers) {
	case 1:
		return (xdr_opaque(xdrsp, (caddr_t)&fhrp->fhr_fh, NFSX_V2FH));
	case 3:
		len = NFSX_V3FH;
		if (!xdr_long(xdrsp, (long*)&len))
			return (0);
		if (!xdr_opaque(xdrsp, (caddr_t)&fhrp->fhr_fh, len))
			return (0);
		if (fhrp->fhr_numsecflavors) {
			if (!xdr_int(xdrsp, &fhrp->fhr_numsecflavors))
				return (0);
			for (i = 0; i < fhrp->fhr_numsecflavors; i++)
				if (!xdr_int(xdrsp, &fhrp->fhr_secflavors[i]))
					return (0);
			return (1);
		} else {
			auth = AUTH_SYS;
			len = 1;
			if (!xdr_long(xdrsp, (long*)&len))
				return (0);
			return (xdr_long(xdrsp, (long*)&auth));
		}
	};
	return (0);
}

/*
 * The mount rpc service
 */
void
mntsrv(struct svc_req *rqstp, SVCXPRT *transp)
{
	struct fhreturn fhr = { 0 };
	struct stat stb;
	struct statfs fsb;
	char host[NI_MAXHOST], numerichost[NI_MAXHOST];
	int lookup_failed = 1;
	struct sockaddr *saddr;
	u_short sport;
	char *local_path = NULL;
	char rpcpath[MNTPATHLEN + 1], dirpath[MAXPATHLEN];
	int bad = 0, defset, hostset;
	sigset_t sighup_mask;
	int numsecflavors, *secflavorsp;
	struct export_entry *export;
	char *export_name;
	
	sigemptyset(&sighup_mask);
	sigaddset(&sighup_mask, SIGHUP);
	saddr = svc_getrpccaller(transp)->buf;
	switch (saddr->sa_family) {
	case AF_INET6:
		sport = ntohs(((struct sockaddr_in6 *)saddr)->sin6_port);
		break;
	case AF_INET:
		sport = ntohs(((struct sockaddr_in *)saddr)->sin_port);
		break;
	default:
		syslog(LOG_ERR, "request from unknown address family");
		return;
	}
	lookup_failed = getnameinfo(saddr, saddr->sa_len, host, sizeof host, 
	    NULL, 0, 0);
	getnameinfo(saddr, saddr->sa_len, numerichost,
	    sizeof numerichost, NULL, 0, NI_NUMERICHOST);
	switch (rqstp->rq_proc) {
	case NULLPROC:
		if (!svc_sendreply(transp, (xdrproc_t)xdr_void, NULL))
			syslog(LOG_ERR, "can't send reply");
		return;
	case MOUNTPROC_MNT:
		if (sport >= IPPORT_RESERVED && resvport_only) {
			syslog(LOG_NOTICE,
			    "mount request from %s from unprivileged port",
			    numerichost);
			svcerr_weakauth(transp);
			return;
		}
		if (!svc_getargs(transp, (xdrproc_t)xdr_dir, rpcpath)) {
			syslog(LOG_NOTICE, "undecodable mount request from %s",
			    numerichost);
			svcerr_decode(transp);
			return;
		}

		export = FindBestExportForAddress(rpcpath, saddr, &export_name);
		if (export == NULL) {
			syslog(LOG_NOTICE, "Bad mount request from %s for %s",
			       numerichost, rpcpath);
			bad = EACCES;
			if (!svc_sendreply(transp, (xdrproc_t)xdr_long,
					   (caddr_t)&bad))
				syslog(LOG_ERR, "Can't send reply about bad mount request");
			sigprocmask(SIG_UNBLOCK, &sighup_mask, NULL);
			return;
		}
		/*
		 * Need to convert rpcpath from something based on export_name to
		 * something based on export->export_path.
		 * First test for the easy case.
		 */
		if (strcmp(export->export_path, export_name) == 0) {
			local_path = strdup(rpcpath);
		} else if (strcmp(export_name, rpcpath) == 0) {
			// Another easy case
			local_path = strdup(export->export_path);
		} else {
			/*
			 * Okay, in this case, rpcpath is <export_name>/<something else>
			 * So we want to build local_ath as <export->export_path>/<something else>
			 */
			char *something_else = rpcpath + strlen(export_name);
			asprintf(&local_path, "%s%s", export->export_path, something_else);
		}
		if (realpath(local_path, dirpath) == NULL ||
		    stat(dirpath, &stb) < 0 ||
		    (!S_ISDIR(stb.st_mode) &&
		     (server_config.dir_only || !S_ISREG(stb.st_mode))) ||
		    statfs(dirpath, &fsb) < 0) {
			chdir("/");	/* Just in case realpath doesn't */
			syslog(LOG_NOTICE,
			       "mount request from %s for non existent path %s",
			       numerichost, dirpath);
			if (debug)
				warnx("stat failed on %s", dirpath);
			bad = ENOENT;	/* We will send error reply later */
		}
		sigprocmask(SIG_BLOCK, &sighup_mask, NULL);
		if (bad) {
			if (!svc_sendreply(transp, (xdrproc_t)xdr_long,
					   (caddr_t)&bad))
				syslog(LOG_ERR, "can't send reply");
			sigprocmask(SIG_UNBLOCK, &sighup_mask, NULL);
			return;
		}
		fhr.fhr_numsecflavors = export->args.ex_numsecflavors;
		fhr.fhr_secflavors = export->args.ex_secflavors;
		fhr.fhr_vers = rqstp->rq_vers;
		/* Get the file handle */
		warnx("dirpath = %s", dirpath);
		if (getfh(dirpath, (fhandle_t*)&fhr.fhr_fh) < 0) {
			bad = errno;
			syslog(LOG_ERR, "can't get fh for %s", dirpath);
			if (!svc_sendreply(transp, (xdrproc_t)xdr_long,
					   (caddr_t)&bad))
				syslog(LOG_ERR, "can't send reply about inability to get fh for %s", dirpath);
			sigprocmask(SIG_UNBLOCK, &sighup_mask, NULL);
			return;
		}
		warnx("Got fhandle for %s", dirpath);
		fhr.fhr_flag = 1;
		{
			char fh_buf[sizeof(fhr.fhr_fh)*2 + 1] = { 0 };
			size_t x;
			for (x = 0; x < sizeof(fhr.fhr_fh); x++)
				sprintf(fh_buf, "%s%02x", fh_buf, fhr.fhr_fh.fh_bytes[x]);
			
			warnx("fhr = { fhr_flag = %d, fhr_vers = %d, fhr_fh = 0x%s, numsecflavors = %d }",
			      fhr.fhr_flag, fhr.fhr_vers, fh_buf, fhr.fhr_numsecflavors);
		}
		if (!svc_sendreply(transp, (xdrproc_t)xdr_fhs,
				   (caddr_t)&fhr)) {
			warn("Could not send fh reply");
			syslog(LOG_ERR, "Can't send fh reply");
		}
		// Need to add the mount to the current_mounts list
		add_mount(rpcpath, dirpath, numerichost);
		if (debug)
			warnx("mount request for %s successful", dirpath);
		if (server_config.dolog)
			syslog(LOG_NOTICE,
			       "mount request succeeded ffrom %s for %s",
			       numerichost, dirpath);
		return;
	case MOUNTPROC_DUMP:
		if (!svc_sendreply(transp, (xdrproc_t)xdr_mlist, (caddr_t)NULL))
			syslog(LOG_ERR, "can't send reply");
		else if (server_config.dolog)
			syslog(LOG_NOTICE,
			    "dump request succeeded from %s",
			    numerichost);
		return;
	case MOUNTPROC_UMNT:
		warnx("umount request");
		if (sport >= IPPORT_RESERVED && server_config.resvport_only) {
			syslog(LOG_NOTICE,
			    "umount request from %s from unprivileged port",
			    numerichost);
			svcerr_weakauth(transp);
			return;
		}
		if (!svc_getargs(transp, (xdrproc_t)xdr_dir, rpcpath)) {
			syslog(LOG_NOTICE, "undecodable umount request from %s",
			    numerichost);
			svcerr_decode(transp);
			return;
		}
		if (!svc_sendreply(transp, (xdrproc_t)xdr_void, (caddr_t)NULL))
			syslog(LOG_ERR, "can't send reply");
		del_mount(numerichost, rpcpath);
		if (server_config.dolog)
			syslog(LOG_NOTICE,
			    "umount request succeeded from %s for %s",
			    numerichost, dirpath);
		return;
	case MOUNTPROC_UMNTALL:
		if (sport >= IPPORT_RESERVED && resvport_only) {
			syslog(LOG_NOTICE,
			    "umountall request from %s from unprivileged port",
			    numerichost);
			svcerr_weakauth(transp);
			return;
		}
		if (!svc_sendreply(transp, (xdrproc_t)xdr_void, (caddr_t)NULL))
			syslog(LOG_ERR, "can't send reply");
		del_mount(numerichost, NULL);
		if (server_config.dolog)
			syslog(LOG_NOTICE,
			    "umountall request succeeded from %s",
			    numerichost);
		return;
	case MOUNTPROC_EXPORT:
		if (!svc_sendreply(transp, (xdrproc_t)xdr_explist, (caddr_t)NULL))
			if (!svc_sendreply(transp, (xdrproc_t)xdr_explist_brief,
			    (caddr_t)NULL))
				syslog(LOG_ERR, "can't send reply");
		if (server_config.dolog)
			syslog(LOG_NOTICE,
			    "export request succeeded from %s",
			    numerichost);
		return;
	default:
		svcerr_noproc(transp);
		return;
	}
}
/*
 * This routine creates and binds sockets on the appropriate
 * addresses. It gets called one time for each transport.
 * It returns 0 upon success, 1 for ingore the call and -1 to indicate
 * bind failed with EADDRINUSE.
 * Any file descriptors that have been created are stored in sock_fd and
 * the total count of them is maintained in sock_fdcnt.
 */
static int
create_service(struct netconfig *nconf)
{
	struct addrinfo hints, *res = NULL;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	struct __rpc_sockinfo si;
	int aicode;
	int fd;
	int nhostsbak;
	int one = 1;
	int r;
	u_int32_t host_addr[4];  /* IPv4 or IPv6 */
	int mallocd_res;
	char *bind_host;
	char **hosts = server_config.bind_addrs;
	
	if ((nconf->nc_semantics != NC_TPI_CLTS) &&
	    (nconf->nc_semantics != NC_TPI_COTS) &&
	    (nconf->nc_semantics != NC_TPI_COTS_ORD))
		return (1);	/* not my type */

	/*
	 * XXX - using RPC library internal functions.
	 */
	if (!__rpc_nconf2sockinfo(nconf, &si)) {
		syslog(LOG_ERR, "cannot get information for %s",
		    nconf->nc_netid);
		return (1);
	}

	/* Get mountd's address on this transport */
	memset(&hints, 0, sizeof hints);
	hints.ai_family = si.si_af;
	hints.ai_socktype = si.si_socktype;
	hints.ai_protocol = si.si_proto;

	/*
	 * Bind to specific IPs if asked to
	 */
	nhostsbak = server_config.naddrs;
	while (nhostsbak > 0) {
		--nhostsbak;
		sock_fd = realloc(sock_fd, (sock_fdcnt + 1) * sizeof(int));
		if (sock_fd == NULL)
			out_of_mem();
		sock_fd[sock_fdcnt++] = -1;	/* Set invalid for now. */
		mallocd_res = 0;

		hints.ai_flags = AI_PASSIVE;

		/*	
		 * XXX - using RPC library internal functions.
		 */
		if ((fd = __rpc_nconf2fd(nconf)) < 0) {
			int non_fatal = 0;
	    		if (errno == EAFNOSUPPORT &&
			    nconf->nc_semantics != NC_TPI_CLTS) 
				non_fatal = 1;
				
			syslog(non_fatal ? LOG_DEBUG : LOG_ERR, 
			    "cannot create socket for %s", nconf->nc_netid);
			if (non_fatal != 0)
				continue;
			exit(1);
		}

		switch (hints.ai_family) {
		case AF_INET:
			if (inet_pton(AF_INET, hosts[nhostsbak],
			    host_addr) == 1) {
				hints.ai_flags |= AI_NUMERICHOST;
			} else {
				/*
				 * Skip if we have an AF_INET6 address.
				 */
				if (inet_pton(AF_INET6, hosts[nhostsbak],
				    host_addr) == 1) {
					close(fd);
					continue;
				}
			}
			break;
		case AF_INET6:
			if (inet_pton(AF_INET6, hosts[nhostsbak],
			    host_addr) == 1) {
				hints.ai_flags |= AI_NUMERICHOST;
			} else {
				/*
				 * Skip if we have an AF_INET address.
				 */
				if (inet_pton(AF_INET, hosts[nhostsbak],
				    host_addr) == 1) {
					close(fd);
					continue;
				}
			}

			/*
			 * We're doing host-based access checks here, so don't
			 * allow v4-in-v6 to confuse things. The kernel will
			 * disable it by default on NFS sockets too.
			 */
			if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one,
			    sizeof one) < 0) {
				syslog(LOG_ERR,
				    "can't disable v4-in-v6 on IPv6 socket");
				exit(1);
			}
			break;
		default:
			break;
		}

		/*
		 * If no hosts were specified, just bind to INADDR_ANY
		 */
		if (strcmp("*", hosts[nhostsbak]) == 0) {
			if (svcport_str == NULL) {
				res = malloc(sizeof(struct addrinfo));
				if (res == NULL) 
					out_of_mem();
				mallocd_res = 1;
				res->ai_flags = hints.ai_flags;
				res->ai_family = hints.ai_family;
				res->ai_protocol = hints.ai_protocol;
				switch (res->ai_family) {
				case AF_INET:
					sin = malloc(sizeof(struct sockaddr_in));
					if (sin == NULL) 
						out_of_mem();
					sin->sin_family = AF_INET;
					sin->sin_port = htons(0);
					sin->sin_addr.s_addr = htonl(INADDR_ANY);
					res->ai_addr = (struct sockaddr*) sin;
					res->ai_addrlen = (socklen_t)
					    sizeof(struct sockaddr_in);
					break;
				case AF_INET6:
					sin6 = malloc(sizeof(struct sockaddr_in6));
					if (sin6 == NULL)
						out_of_mem();
					sin6->sin6_family = AF_INET6;
					sin6->sin6_port = htons(0);
					sin6->sin6_addr = in6addr_any;
					res->ai_addr = (struct sockaddr*) sin6;
					res->ai_addrlen = (socklen_t)
					    sizeof(struct sockaddr_in6);
					break;
				default:
					syslog(LOG_ERR, "bad addr fam %d",
					    res->ai_family);
					exit(1);
				}
			} else { 
				if ((aicode = getaddrinfo(NULL, svcport_str,
				    &hints, &res)) != 0) {
					syslog(LOG_ERR,
					    "cannot get local address for %s: %s",
					    nconf->nc_netid,
					    gai_strerror(aicode));
					close(fd);
					continue;
				}
			}
		} else {
			if ((aicode = getaddrinfo(hosts[nhostsbak], svcport_str,
			    &hints, &res)) != 0) {
				syslog(LOG_ERR,
				    "cannot get local address for %s: %s",
				    nconf->nc_netid, gai_strerror(aicode));
				close(fd);
				continue;
			}
		}

		/* Store the fd. */
		sock_fd[sock_fdcnt - 1] = fd;

		/* Now, attempt the bind. */
		r = bindresvport_sa(fd, res->ai_addr);
		if (r != 0) {
			if (errno == EADDRINUSE && mallocd_svcport != 0) {
				if (mallocd_res != 0) {
					free(res->ai_addr);
					free(res);
				} else
					freeaddrinfo(res);
				return (-1);
			}
			syslog(LOG_ERR, "bindresvport_sa: %m");
			exit(1);
		}

		if (svcport_str == NULL) {
			svcport_str = malloc(NI_MAXSERV * sizeof(char));
			if (svcport_str == NULL)
				out_of_mem();
			mallocd_svcport = 1;

			if (getnameinfo(res->ai_addr,
			    res->ai_addr->sa_len, NULL, NI_MAXHOST,
			    svcport_str, NI_MAXSERV * sizeof(char),
			    NI_NUMERICHOST | NI_NUMERICSERV))
				errx(1, "Cannot get port number");
		}
		if (mallocd_res != 0) {
			free(res->ai_addr);
			free(res);
		} else
			freeaddrinfo(res);
		res = NULL;
	}
	return (0);
}

/*
 * Called after all the create_service() calls have succeeded, to complete
 * the setup and registration.
 */
static void
complete_service(struct netconfig *nconf, char *port_str)
{
	struct addrinfo hints, *res = NULL;
	struct __rpc_sockinfo si;
	struct netbuf servaddr;
	SVCXPRT	*transp = NULL;
	int aicode, fd, nhostsbak;
	int registered = 0;

	printf("WOOHOO\n");
	if ((nconf->nc_semantics != NC_TPI_CLTS) &&
	    (nconf->nc_semantics != NC_TPI_COTS) &&
	    (nconf->nc_semantics != NC_TPI_COTS_ORD))
		return;	/* not my type */

	/*
	 * XXX - using RPC library internal functions.
	 */
	if (!__rpc_nconf2sockinfo(nconf, &si)) {
		syslog(LOG_ERR, "cannot get information for %s",
		    nconf->nc_netid);
		return;
	}

	nhostsbak = server_config.naddrs;
	fprintf(stderr, "%s(%d):  nhostbak = %d\n", __FUNCTION__, __LINE__, nhostsbak);
	while (nhostsbak > 0) {
		--nhostsbak;
		if (sock_fdpos >= sock_fdcnt) {
			/* Should never happen. */
			syslog(LOG_ERR, "Ran out of socket fd's");
			return;
		}
		fd = sock_fd[sock_fdpos++];
		if (fd < 0)
			continue;

		if (nconf->nc_semantics != NC_TPI_CLTS)
			listen(fd, SOMAXCONN);

		if (nconf->nc_semantics == NC_TPI_CLTS )
			transp = svc_dg_create(fd, 0, 0);
		else 
			transp = svc_vc_create(fd, RPC_MAXDATASIZE,
			    RPC_MAXDATASIZE);

		if (transp != (SVCXPRT *) NULL) {
			if (!svc_reg(transp, MOUNTPROG, MOUNTVERS, mntsrv,
			    NULL)) 
				syslog(LOG_ERR,
				    "can't register %s MOUNTVERS service",
				    nconf->nc_netid);
			if (!server_config.force_v2) {
				if (!svc_reg(transp, MOUNTPROG, MOUNTVERS3,
				    mntsrv, NULL)) 
					syslog(LOG_ERR,
					    "can't register %s MOUNTVERS3 service",
					    nconf->nc_netid);
			}
		} else 
			syslog(LOG_WARNING, "can't create %s services",
			       nconf->nc_netid);

		if (registered == 0) {
			registered = 1;
			memset(&hints, 0, sizeof hints);
			hints.ai_flags = AI_PASSIVE;
			hints.ai_family = si.si_af;
			hints.ai_socktype = si.si_socktype;
			hints.ai_protocol = si.si_proto;

			if ((aicode = getaddrinfo(NULL, port_str, &hints,
			    &res)) != 0) {
				syslog(LOG_ERR, "cannot get local address: %s",
				    gai_strerror(aicode));
				exit(1);
			}

			servaddr.buf = malloc(res->ai_addrlen);
			memcpy(servaddr.buf, res->ai_addr, res->ai_addrlen);
			servaddr.len = res->ai_addrlen;

			rpcb_set(MOUNTPROG, MOUNTVERS, nconf, &servaddr);
			rpcb_set(MOUNTPROG, MOUNTVERS3, nconf, &servaddr);

			xcreated++;
			freeaddrinfo(res);
		}
	} /* end while */
}

/*
 * Clear out sockets after a failure to bind one of them, so that the
 * cycle of socket creation/binding can start anew.
 */
static void
clearout_service(void)
{
	int i;

	for (i = 0; i < sock_fdcnt; i++) {
		if (sock_fd[i] >= 0) {
			shutdown(sock_fd[i], SHUT_RDWR);
			close(sock_fd[i]);
		}
	}
}
void
init_rpc(void)
{
	int maxrec = RPC_MAXDATASIZE;
	void *nc_handle;
	struct netconfig *nconf;
	
	rpcb_unset(MOUNTPROG, MOUNTVERS, NULL);
	rpcb_unset(MOUNTPROG, MOUNTVERS3, NULL);
	rpc_control(RPC_SVC_CONNMAXREC_SET, &maxrec);

	if (server_config.resvport_only == 0) {
		sysctlbyname("vfs.nfsrv.nfs_privport", NULL, NULL,
			     &server_config.resvport_only,
			     sizeof(server_config.resvport_only));
	}

	nc_handle = setnetconfig();
	while ((nconf = getnetconfig(nc_handle)) != NULL) {
		if (nconf->nc_flag & NC_VISIBLE) {
			int ret;
			
			if (server_config.have_v6 == 0 &&
			    strcmp(nconf->nc_protofmly, "inet6") == 0)
				continue;
			ret = create_service(nconf);
			warnx("ret = %d, svcport_str = %s", ret, svcport_str);
			if (ret == 0) {
				complete_service(nconf, svcport_str);
			}
		}
	}

	return;
}

void
service_rpc(void) {
	fd_set readfds;
	readfds = svc_fdset;
	
	if (debug && verbose)
		fprintf(stderr, "Calling select, svc_maxfd = %d\n", svc_maxfd);
	switch (select(svc_maxfd + 1, &readfds, NULL, NULL, NULL)) {
	case -1:
		warn("select");
		break;
	case 0:
		warnx("select returnd 0");
		break;
	default:
		if (debug)
			warnx("Calling getreqset");
		svc_getreqset(&readfds);
	}
	return;
}

void
stop_rpc(void)
{
	rpcb_unset(MOUNTPROG, MOUNTVERS, NULL);
	rpcb_unset(MOUNTPROG, MOUNTVERS3, NULL);
	return;
}
