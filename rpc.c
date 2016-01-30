/*
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
	char	ml_dirp[MNTPATHLEN+1];
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
add_mount(char *dirp, char *hostp)
{
	struct mountlist *mlp, **mlpp;
	FILE *mlfile;

	mlpp = &current_mounts;
	mlp = current_mounts;
	while (mlp) {
		if (!strcmp(mlp->ml_host, hostp) && !strcmp(mlp->ml_dirp, dirp))
			return;
		mlpp = &mlp->ml_next;
		mlp = mlp->ml_next;
	}
	mlp = (struct mountlist *)malloc(sizeof (*mlp));
	if (mlp == (struct mountlist *)NULL)
		out_of_mem();
	strncpy(mlp->ml_host, hostp, MNTNAMLEN);
	mlp->ml_host[MNTNAMLEN] = '\0';
	strncpy(mlp->ml_dirp, dirp, MNTPATHLEN);
	mlp->ml_dirp[MNTPATHLEN] = '\0';
	mlp->ml_next = (struct mountlist *)NULL;
	*mlpp = mlp;
	if ((mlfile = fopen(_PATH_RMOUNTLIST, "a")) == NULL) {
		syslog(LOG_ERR, "can't update %s", _PATH_RMOUNTLIST);
		return;
	}
	fprintf(mlfile, "%s %s\n", mlp->ml_host, mlp->ml_dirp);
	fclose(mlfile);
}

/*
 * Xdr conversion for a dirpath string
 */
static int
xdr_dir(XDR *xdrsp, char *dirp)
{
	return (xdr_string(xdrsp, &dirp, MNTPATHLEN));
}

int
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
		strp = &mlp->ml_dirp[0];
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

void
init_rpc(void)
{
	int maxrec = RPC_MAXDATASIZE;
	rpcb_unset(MOUNTPROG, MOUNTVERS, NULL);
	rpcb_unset(MOUNTPROG, MOUNTVERS3, NULL);
	rpc_control(RPC_SVC_CONNMAXREC_SET, &maxrec);
	
	return;
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
			bad = EPERM;
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
		if (getfh(dirpath, (fhandle_t*)&fhr.fhr_fh) < 0) {
			bad = errno;
			syslog(LOG_ERR, "can't get fh for %s", dirpath);
			if (!svc_sendreply(transp, (xdrproc_t)xdr_long,
					   (caddr_t)&bad))
				syslog(LOG_ERR, "can't send reply about inability to get fh for %s", dirpath);
			sigprocmask(SIG_UNBLOCK, &sighup_mask, NULL);
			return;
		}
		if (!svc_sendreply(transp, (xdrproc_t)xdr_fhs,
				   (caddr_t)&fhr))
			syslog(LOG_ERR, "Can't send fh reply");
		// Need to add the mount to the current_mounts list
		add_mount(dirpath, lookup_failed ? numerichost : host);
		if (debug)
			warnx("mount request for %s successful", dirpath);
		if (server_config.dolog)
			syslog(LOG_NOTICE,
			       "mount request succeeded ffrom %s for %s",
			       numerichost, dirpath);
		return;
#if 0
		/*
		 * Get the real pathname and make sure it is a directory
		 * or a regular file if the -r option was specified
		 * and it exists.
		 */
		if (realpath(rpcpath, dirpath) == NULL ||
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

		/* Check in the exports list */
		sigprocmask(SIG_BLOCK, &sighup_mask, NULL);
		ep = ex_search(&fsb.f_fsid);
		hostset = defset = 0;
		if (ep && (chk_host(ep->ex_defdir, saddr, &defset, &hostset,
		    &numsecflavors, &secflavorsp) ||
		    ((dp = dirp_search(ep->ex_dirl, dirpath)) &&
		      chk_host(dp, saddr, &defset, &hostset, &numsecflavors,
		       &secflavorsp)) ||
		    (defset && scan_tree(ep->ex_defdir, saddr) == 0 &&
		     scan_tree(ep->ex_dirl, saddr) == 0))) {
			if (bad) {
				if (!svc_sendreply(transp, (xdrproc_t)xdr_long,
				    (caddr_t)&bad))
					syslog(LOG_ERR, "can't send reply");
				sigprocmask(SIG_UNBLOCK, &sighup_mask, NULL);
				return;
			}
			if (hostset & DP_HOSTSET) {
				fhr.fhr_flag = hostset;
				fhr.fhr_numsecflavors = numsecflavors;
				fhr.fhr_secflavors = secflavorsp;
			} else {
				fhr.fhr_flag = defset;
				fhr.fhr_numsecflavors = ep->ex_defnumsecflavors;
				fhr.fhr_secflavors = ep->ex_defsecflavors;
			}
			fhr.fhr_vers = rqstp->rq_vers;
			/* Get the file handle */
			memset(&fhr.fhr_fh, 0, sizeof(nfsfh_t));
			if (getfh(dirpath, (fhandle_t *)&fhr.fhr_fh) < 0) {
				bad = errno;
				syslog(LOG_ERR, "can't get fh for %s", dirpath);
				if (!svc_sendreply(transp, (xdrproc_t)xdr_long,
				    (caddr_t)&bad))
					syslog(LOG_ERR, "can't send reply");
				sigprocmask(SIG_UNBLOCK, &sighup_mask, NULL);
				return;
			}
			if (!svc_sendreply(transp, (xdrproc_t)xdr_fhs,
			    (caddr_t)&fhr))
				syslog(LOG_ERR, "can't send reply");
			if (!lookup_failed)
				add_mlist(host, dirpath);
			else
				add_mlist(numerichost, dirpath);
			if (debug)
				warnx("mount successful");
			if (server_config.dolog)
				syslog(LOG_NOTICE,
				    "mount request succeeded from %s for %s",
				    numerichost, dirpath);
		} else {
			bad = EACCES;
			syslog(LOG_NOTICE,
			    "mount request denied from %s for %s",
			    numerichost, dirpath);
		}

		if (bad && !svc_sendreply(transp, (xdrproc_t)xdr_long,
		    (caddr_t)&bad))
			syslog(LOG_ERR, "can't send reply");
		sigprocmask(SIG_UNBLOCK, &sighup_mask, NULL);
		return;
#endif
	case MOUNTPROC_DUMP:
		if (!svc_sendreply(transp, (xdrproc_t)xdr_mlist, (caddr_t)NULL))
			syslog(LOG_ERR, "can't send reply");
		else if (server_config.dolog)
			syslog(LOG_NOTICE,
			    "dump request succeeded from %s",
			    numerichost);
		return;
#if 0
	case MOUNTPROC_UMNT:
		if (sport >= IPPORT_RESERVED && resvport_only) {
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
		if (realpath(rpcpath, dirpath) == NULL) {
			syslog(LOG_NOTICE, "umount request from %s "
			    "for non existent path %s",
			    numerichost, dirpath);
		}
		if (!svc_sendreply(transp, (xdrproc_t)xdr_void, (caddr_t)NULL))
			syslog(LOG_ERR, "can't send reply");
		if (!lookup_failed)
			del_mlist(host, dirpath);
		del_mlist(numerichost, dirpath);
		if (dolog)
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
		if (!lookup_failed)
			del_mlist(host, NULL);
		del_mlist(numerichost, NULL);
		if (dolog)
			syslog(LOG_NOTICE,
			    "umountall request succeeded from %s",
			    numerichost);
		return;
	case MOUNTPROC_EXPORT:
		if (!svc_sendreply(transp, (xdrproc_t)xdr_explist, (caddr_t)NULL))
			if (!svc_sendreply(transp, (xdrproc_t)xdr_explist_brief,
			    (caddr_t)NULL))
				syslog(LOG_ERR, "can't send reply");
		if (dolog)
			syslog(LOG_NOTICE,
			    "export request succeeded from %s",
			    numerichost);
		return;
#endif
	default:
		svcerr_noproc(transp);
		return;
	}
}
