/*
 * Routines to support mounting (and unmounting).
 */
#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <errno.h>
#include <string.h>

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
	struct iovec *iov;
	struct xvfsconf vfc;
	char errmsg[255];
	int iovlen;
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
		if ((sfs->f_flags & MNT_EXPORTED) == 0)
			continue;

		if (vfc.vfc_flags & VFCF_NETWORK)
			continue;

#define SET_STR(iov, str) do { \
			(iov).iov_base = str; \
			(iov).iov_len = strlen(str) + 1; \
		} while (0)
		SET_STR(iov[1], sfs->f_fstypename);
		SET_STR(iov[3], sfs->f_mntonname);
		SET_STR(iov[5], sfs->f_mntfromname);
#undef SET_STR
		errmsg[0] = 0;

		if (nmount(iov, iovlen, sfs->f_flags) == -1 &&
		    errno != ENOENT && errno != ENOTSUP && errno != EXDEV)
			warn("Can't delete export for %s: %s", sfs->f_mntonname, errmsg);
	}
}
