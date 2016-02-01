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
uint8_t *
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
	return (uint8_t*)(p);
}

/*
 * Make a netmask according to the specified prefix length. The ss_family
 * and other non-address fields must be initialised before calling this.
 */
int
make_netmask(struct sockaddr_storage *ssp, int bitlen)
{
	uint8_t *p;
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

/*
 * Compare a sockaddr with a struct network_entry.
 * Returns NET_MATCH_NONE if it isn't a match,
 * NET_MATCH_HOST if it's a perfect match, and
 * the number of bits in the network mask otherwise.
 */
int
network_compare(struct network_entry *network,
		struct sockaddr *sap)
{
	uint8_t *addr_bytes,
		*network_bytes,
		*mask_bytes;
	int nbytes;
	size_t i;
	
	// First check -- for errors
	if (network == NULL ||
	    network->network == NULL ||
	    sap == NULL)
		return NET_MATCH_NONE;

	// Second check -- families
	if (network->network->sa_family != sap->sa_family)
		return NET_MATCH_NONE;
	// Now a sanity check
	if (network->mask &&
	    network->mask->sa_family != network->network->sa_family)
		return NET_MATCH_NONE;

	addr_bytes = sa_rawaddr(sap, &nbytes);
	network_bytes = sa_rawaddr(network->network, NULL);

	// Easy check:  if mask is NULL, just do a memcmp
	if (network->mask == NULL) {
		if (memcmp(addr_bytes, network_bytes, nbytes) == 0) {
			return NET_MATCH_HOST;
		} else {
			return NET_MATCH_NONE;
		}
	}
	// Okay, have to compare with the mask
	mask_bytes = sa_rawaddr(network->mask, NULL);
	for (i = 0; i < nbytes; i++) {
		if ((addr_bytes[i] & mask_bytes[i]) !=
		    (network_bytes[i] & mask_bytes[i])) {
			return NET_MATCH_NONE;
		}
	}
	return netmask_to_masklen(network->mask);
}

int
check_ipv6(void)
{
	int s = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (s < 0)
		return 0;
	close(s);
	return 1;
}
