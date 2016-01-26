/*
 * Network-support routines for mountd.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <err.h>
#include <errno.h>
#include <syslog.h>
#include <pwd.h>
#include <grp.h>
#include <ctype.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mount.h>

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
/*
 * Return a pointer to the part of the sockaddr that contains the
 * raw address, and set *nbytes to its length in bytes. Returns
 * NULL if the address family is unknown.
 */
void *
sa_rawaddr(struct sockaddr *sa, int *nbytes) {
	void *p;
	int len;

	switch (sa->sa_family) {
	case AF_INET:
		len = sizeof(((struct sockaddr_in *)sa)->sin_addr);
		p = &((struct sockaddr_in *)sa)->sin_addr;
		break;
	case AF_INET6:
		len = sizeof(((struct sockaddr_in6 *)sa)->sin6_addr);
		p = &((struct sockaddr_in6 *)sa)->sin6_addr;
		break;
	default:
		p = NULL;
		len = 0;
	}

	if (nbytes != NULL)
		*nbytes = len;
	return (p);
}

/*
 * Make a netmask according to the specified prefix length. The ss_family
 * and other non-address fields must be initialised before calling this.
 */
int
make_netmask(struct sockaddr_storage *ssp, int bitlen)
{
	u_char *p;
	int bits, i, len;

	if ((p = sa_rawaddr((struct sockaddr *)ssp, &len)) == NULL)
		return (-1);
	if (bitlen > len * CHAR_BIT)
		return (-1);

	for (i = 0; i < len; i++) {
		bits = (bitlen > CHAR_BIT) ? CHAR_BIT : bitlen;
		*p++ = (u_char)~0 << (CHAR_BIT - bits);
		bitlen -= bits;
	}
	return 0;
}

/*
 * Given a netmask ("-mask=blah"), convert it into mask length,
 * as in a CIDR.
 * Returns -1 on error.
 */
int
netmask_to_masklen(struct sockaddr *sap)
{
	int retval = 0;
	uint8_t *bp, *endp;
	int maxbits, byte_count;
	
	bp = sa_rawaddr(sap, &byte_count);
	if (bp == NULL) {
		errno = EFAULT;
		return -1;
	}
	endp = bp + byte_count;
	maxbits = byte_count * NBBY;

	for (retval = 0;
	     bp < endp;
	     bp++) {
		int bindex;
		if (*bp == 0xff) {
			retval += NBBY;
			continue;
		}
		if (*bp == 0) {
			break;
		}
		if (~*bp & (uint8_t)(~*bp + 1)) {
			warnx("netmask is not a nice mask");
			errno = EINVAL;
			return -1;
		}
#if 1
		bindex = ffs(*bp);
		if (debug)
			warnx("*** bindex for %#x = %d\n", *bp, bindex);
		if (bindex == 0)
			abort();
		retval += (NBBY - bindex + 1);
#else
		// This loop is at most 7 times, so not too slow
		while (*bp) {
			*bp <<= 1;
			retval += 1;
		}
#endif
		bp++;
		break;
	}
	while (bp < endp) {
		if (*bp != 0) {
			warnx("netmask doesn't end in all zeroes");
			errno = EINVAL;
			return -1;
		}
		bp++;
	}
	return retval;
}
