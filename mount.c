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
/*
 * Routines to support mounting (and unmounting).
 */
#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>

#include <sys/param.h>
#include <sys/fcntl.h>
#include <sys/linker.h>
#include <sys/module.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/syslog.h>

#include <fs/nfs/nfsport.h>

#include "mountd.h"

// Taken directly from sbin/mount/getmntopts.c
static void
build_iovec(struct iovec **iov, int *iovlen, const char *name, void *val,
	    size_t len)
{
	int i;

	if (*iovlen < 0)
		return;
	i = *iovlen;
	*iov = realloc(*iov, sizeof **iov * (i + 2));
	if (*iov == NULL) {
		*iovlen = -1;
		return;
	}
	(*iov)[i].iov_base = strdup(name);
	(*iov)[i].iov_len = strlen(name) + 1;
	i++;
	(*iov)[i].iov_base = val;
	if (len == (size_t)-1) {
		if (val != NULL)
			len = strlen(val) + 1;
		else
			len = 0;
	}
	(*iov)[i].iov_len = (int)len;
	*iovlen = ++i;
}

/*
 * Called before reading the export file(s).
 * This tells the kernel to stop exporting filesystems.
 */
void
UnexportFilesystems(void)
{
	struct statfs *sfs, *mounts;
	struct xucred anon;
	struct export_args export = { .ex_flags = MNT_DELEXPORT };
	struct nfsex_args eargs;
	struct iovec *iov = NULL;
	struct xvfsconf vfc;
	char errmsg[255];
	int iovlen = 0;
	int mount_count;
	size_t indx;
	
	// See get_exportlist() from original mountd.c

	mount_count = getmntinfo(&mounts, MNT_NOWAIT);

	if (mount_count > 0) {
		build_iovec(&iov, &iovlen, "fstype", NULL, 0);
		build_iovec(&iov, &iovlen, "fspath", NULL, 0);
		build_iovec(&iov, &iovlen, "from", NULL, 0);
		build_iovec(&iov, &iovlen, "update", NULL, 0);
		build_iovec(&iov, &iovlen, "export", &export, sizeof(export));
		build_iovec(&iov, &iovlen, "errmsg", errmsg, sizeof(errmsg));
	}

	for (indx = 0; indx < mount_count; indx++) {
		sfs = &mounts[indx];
		if (getvfsbyname(sfs->f_fstypename, &vfc) != 0) {
			warn("getvfsbyname(%s)", sfs->f_fstypename);
			continue;
		}
		// If it's not exported, nothing to do
		if ((sfs->f_flags & MNT_EXPORTED) == 0) {
			if (debug)
				warnx("Skipping %s because it is not exported", sfs->f_mntonname);
			continue;
		}

		if (vfc.vfc_flags & VFCF_NETWORK) {
			if (debug)
				warnx("Skipping %s becasue it is a network filesystem", sfs->f_mntonname);
			continue;
		}

#define SET_STR(iov, str) do { \
			(iov).iov_base = str; \
			(iov).iov_len = strlen(str) + 1; \
		} while (0)
		SET_STR(iov[1], sfs->f_fstypename);
		SET_STR(iov[3], sfs->f_mntonname);
		SET_STR(iov[5], sfs->f_mntfromname);
#undef SET_STR
		errmsg[0] = 0;

		if (debug)
			warnx("About to unexport %s", sfs->f_mntonname);
		if (nmount(iov, iovlen, sfs->f_flags) == -1 &&
		    errno != ENOENT && errno != ENOTSUP && errno != EXDEV)
			warn("Can't delete export for %s: %s", sfs->f_mntonname, errmsg);
	}
	if (iov != NULL) {
		free(iov[0].iov_base); // fstype
		free(iov[2].iov_base); // fspath
		free(iov[4].iov_base); // from
		free(iov[6].iov_base); // update
		free(iov[8].iov_base); // export
		free(iov[10].iov_base); // errmsg
		free(iov);
		iovlen = 0;
	}
}

/*
 * Iterate through the tree, and mark each filesystem as exportable.
 * Also set up the networking bits for the kernel.
 */
void
ExportFilesystems(void)
{
	IterateTree(^(struct export_node *exp) {
			size_t entry;
			struct iovec *iov = NULL;
			char errmsg[255];
			struct export_args export = { 0 };
			int iovlen = 0;
			
			build_iovec(&iov, &iovlen, "fstype", NULL, 0);
			build_iovec(&iov, &iovlen, "fspath", NULL, 0);
			build_iovec(&iov, &iovlen, "from", NULL, 0);
			build_iovec(&iov, &iovlen, "update", NULL, 0);
			build_iovec(&iov, &iovlen, "export", &export, sizeof(export));
			build_iovec(&iov, &iovlen, "errmsg", errmsg, sizeof(errmsg));
			
			fprintf(stderr, "\texp->export_count = %zd\n", exp->export_count);
			for (entry = 0; entry < exp->export_count; entry++) {
				struct export_entry *ep = exp->exports[entry];
				struct statfs sfs;
				size_t net_entry;
				char *real_path;
				
				real_path = realpath(ep->export_path, NULL);
				if (real_path == NULL) {
					warn("Could not export %s -- not a real path", ep->export_path);
					continue;
				}
				if (statfs(real_path, &sfs) == -1) {
					warn("Could not find %s (really %s), cannot export", real_path, ep->export_path);
					free(real_path);
					continue;
				}
				if ((ep->export_flags & OPT_ALLDIRS) == 0 &&
				    strcmp(real_path, sfs.f_mntonname) != 0) {
					warn("-alldirs specified, but %s is not a mount point", ep->export_path);
					free(real_path);
					continue;
				}
#define SET_STR(iov, str) do {						\
					(iov).iov_base = str;		\
					(iov).iov_len = strlen(str) + 1; \
				} while (0)
				SET_STR(iov[1], sfs.f_fstypename);
				SET_STR(iov[3], sfs.f_mntonname);
				SET_STR(iov[5], sfs.f_mntfromname);
#undef SET_STR
				
#define PRINTIOV(iov, indx) do {					\
					fprintf(stderr, "******%s = %s\n", iov[indx].iov_base, iov[indx+1].iov_base); \
				} while (0)
				PRINTIOV(iov, 0);
				PRINTIOV(iov, 2);
				PRINTIOV(iov, 4);
				
				for (net_entry = 0; net_entry < ep->network_count; net_entry++) {
					export = ep->args;
					export.ex_addr = ep->entries[net_entry].network;
					export.ex_addrlen = export.ex_addr->sa_len;
					if (ep->entries[net_entry].mask) {
						export.ex_mask = ep->entries[net_entry].mask;
						export.ex_masklen = export.ex_mask->sa_len;
					} else {
						export.ex_mask = NULL;
						export.ex_masklen = 0;
					}
					export.ex_flags |= MNT_EXPORTED;
					if (debug) {
						warnx("About to export %s", sfs.f_mntonname);
						if (verbose) {
							char name[255];
							struct sockaddr *sap = ep->entries[net_entry].network;
							if (getnameinfo(sap, sap->sa_len, name, sizeof(name), NULL, 0, NI_NUMERICHOST) == -1) {
								strcpy(name, "<unknown>");
							}
							if (export.ex_mask) {
								warnx("to %s/%d", name, netmask_to_masklen(export.ex_mask));
							} else {
								warnx("to %s", name);
							}
						}
					}
					errmsg[0] = 0;
					if (nmount(iov, iovlen, sfs.f_flags) == -1) {
						warn("Cannot export %s: %s", sfs.f_mntonname, errmsg);
					}
				}
				if (exp->default_export.export_path) {
					// Export the default entry
					export = exp->default_export.args;
					export.ex_flags |= MNT_EXPORTED;
					export.ex_addr = export.ex_mask = NULL;
					export.ex_addrlen = export.ex_masklen = 0;
					if (debug) {
						warnx("About to default export %s", sfs.f_mntonname);
					}
					errmsg[0] = 0;
					if (nmount(iov, iovlen, sfs.f_flags) == -1) {
						warn("Cannot defaul texport %s: %s", sfs.f_mntonname, errmsg);
					}
				}
			}
			free(iov[0].iov_base); // fstype
			free(iov[2].iov_base); // fspath
			free(iov[4].iov_base); // from
			free(iov[6].iov_base); // update
			free(iov[8].iov_base); // export
			free(iov[10].iov_base); // errmsg
			free(iov);
			
			return 0;
		});
}
