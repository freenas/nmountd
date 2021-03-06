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

enum option_type {
	UNKNOWN = 0,
	OPT_MNT,
	OPT_MOUNTD,
	OPT_CRED,
	OPT_SEC,
	OPT_INDEX,
};
struct export_options {
	const char *name;	// Including the -
	enum option_type type;
	int value;
};

/*
 * This is a convenience datatype used by the parser
 * only.  It converts it to the real datatype when done.
 */
struct export_network_list {
	size_t	count;	// Number of entries
	struct network_entry	*entries;
};

/*
 * parser-internal mapping of path to export name.
 */
struct export_mount {
	char *export_name;
	char *real_name;
};

/*
 * Table of options in an export line.
 */
static struct export_options export_options[] = {
	{ "-maproot", OPT_CRED, OPT_MAP_ROOT, },
	{ "-mapall", OPT_CRED, OPT_MAP_ALL, },
	{ "-sec", OPT_SEC, OPT_SECLIST, },
	{ "-ro", OPT_MNT, MNT_EXRDONLY, },
	{ "-o", OPT_MNT, MNT_EXRDONLY, },
	{ "-public", OPT_MNT, MNT_EXPUBLIC, },
	{ "-webnfs", OPT_MNT, MNT_EXPUBLIC | MNT_EXRDONLY | MNT_EXPORTANON, },
	{ "-alldirs", OPT_MOUNTD, OPT_ALLDIRS, },
	{ "-index", OPT_INDEX, OPT_INDEXFILE, },
	{ "-quite", OPT_MOUNTD, OPT_QUIET, },
	{ 0, 0, 0 },
};
	
	
/*
 * Similar to strsep(), but it allows for quoted strings
 * and escaped characters.
 *
 * It returns the string (or NULL, if *stringp is NULL),
 * which is a de-quoted version of the string if necessary.
 *
 * It modifies *stringp in place.
 */
static char *
strsep_quote(char **stringp, const char *delim)
{
	char *srcptr, *dstptr, *retval;
	char quot = 0;
	
	if (stringp == NULL || *stringp == NULL)
		return (NULL);

	srcptr = dstptr = retval = *stringp;

	while (*srcptr) {
		/*
		 * We're looking for several edge cases here.
		 * First:  if we're in quote state (quot != 0),
		 * then we ignore the delim characters, but otherwise
		 * process as normal, unless it is the quote character.
		 * Second:  if the current character is a backslash,
		 * we take the next character as-is, without checking
		 * for delim, quote, or backslash.  Exception:  if the
		 * next character is a NUL, that's the end of the string.
		 * Third:  if the character is a quote character, we toggle
		 * quote state.
		 * Otherwise:  check the current character for NUL, or
		 * being in delim, and end the string if either is true.
		 */
		if (*srcptr == '\\') {
			srcptr++;
			/*
			 * The edge case here is if the next character
			 * is NUL, we want to stop processing.  But if
			 * it's not NUL, then we simply want to copy it.
			 */
			if (*srcptr) {
				*dstptr++ = *srcptr++;
			}
			continue;
		}
		if (quot == 0 && (*srcptr == '\'' || *srcptr == '"')) {
			quot = *srcptr++;
			continue;
		}
		if (quot && *srcptr == quot) {
			/* End of the quoted part */
			quot = 0;
			srcptr++;
			continue;
		}
		if (!quot && strchr(delim, *srcptr))
			break;
		*dstptr++ = *srcptr++;
	}

	*stringp = (*srcptr == '\0') ? NULL : srcptr + 1;
	*dstptr = 0; /* Terminate the string */
	return (retval);
}

static char *
get_line(FILE *fp)
{
	char *line = NULL;
	size_t linesize = 0;
	char *p, *cp;
	size_t len;
	int totlen, cont_line;

	/*
	 * Loop around ignoring blank lines and getting all continuation lines.
	 */
	totlen = 0;
	do {
		if ((p = fgetln(fp, &len)) == NULL)
			return (0);
		if (debug)
			fprintf(stderr, "line = %s\n", p);
		
		cp = p + len - 1;
		cont_line = 0;
		while (cp >= p &&
		    (*cp == ' ' || *cp == '\t' || *cp == '\n' || *cp == '\\')) {
			if (*cp == '\\')
				cont_line = 1;
			cp--;
			len--;
		}
		if (cont_line) {
			*++cp = ' ';
			len++;
		}
		if (linesize < len + totlen + 1) {
			linesize = len + totlen + 1;
			line = realloc(line, linesize);
			if (line == NULL) {
				warn("Could not allocate %zd bytes", linesize);
				return NULL;
			}
		}
		memcpy(line + totlen, p, len);
		totlen += len;
		line[totlen] = '\0';
	} while (totlen == 0 || cont_line);
	return (line);
}


/*
 * An export line has a horrible free format, but is broken down into
 * three sections.
 * First is a list of one or more export filesystems.  All filesystems
 * must be absolute paths.
 * Second is a list of zero or more options -- these are options that
 * are either passed down to the nmount call, or options that are used
 * by mountd for processing the mount request.
 * Last is a list of zero or more networks/hosts.
 *
 * And lastly, there's one special case:  "V4:/path [-sec=]".  That
 * specifies the NFSv4 root, and the security options for it.  Only
 * one of these per system.
 */
/*
 * Parse a colon separated list of security flavors
 */
static int
parsesec(char *seclist, struct export_args *eap)
{
	char *cp, savedc;
	int flavor;

	eap->ex_numsecflavors = 0;
	for (;;) {
		cp = strchr(seclist, ':');
		if (cp) {
			savedc = *cp;
			*cp = '\0';
		}

		if (!strcmp(seclist, "sys"))
			flavor = AUTH_SYS;
		else if (!strcmp(seclist, "krb5"))
			flavor = RPCSEC_GSS_KRB5;
		else if (!strcmp(seclist, "krb5i"))
			flavor = RPCSEC_GSS_KRB5I;
		else if (!strcmp(seclist, "krb5p"))
			flavor = RPCSEC_GSS_KRB5P;
		else {
			if (cp)
				*cp = savedc;
			warnx("bad sec flavor: %s", seclist);
			return (1);
		}
		if (eap->ex_numsecflavors == MAXSECFLAVORS) {
			if (cp)
				*cp = savedc;
			warnx("too many sec flavors: %s", seclist);
			return (1);
		}
		eap->ex_secflavors[eap->ex_numsecflavors] = flavor;
		eap->ex_numsecflavors++;
		if (cp) {
			*cp = savedc;
			seclist = cp + 1;
		} else {
			break;
		}
	}
	return (0);
}

/*
 * Parse a description of a credential.
 */
static void
parsecred(char *namelist, struct xucred *cr)
{
	char *name;
	int cnt;
	char *names;
	struct passwd *pw;
	struct group *gr;
	gid_t groups[XU_NGROUPS + 1];
	int ngroups;

	cr->cr_version = XUCRED_VERSION;
	/*
	 * Set up the default unprivileged user.
	 */
	cr->cr_uid = -2;
	cr->cr_groups[0] = -2;
	cr->cr_ngroups = 1;
	/*
	 * Get the user's password table entry.
	 */
	names = strsep(&namelist, " \t\n");
	name = strsep(&names, ":");
	if (isdigit(*name) || *name == '-')
		pw = getpwuid(atoi(name));
	else
		pw = getpwnam(name);
	/*
	 * Credentials specified as those of a user.
	 */
	if (names == NULL) {
		if (pw == NULL) {
			warnx("unknown user: %s", name);
			return;
		}
		cr->cr_uid = pw->pw_uid;
		ngroups = XU_NGROUPS + 1;
		if (getgrouplist(pw->pw_name, pw->pw_gid, groups, &ngroups))
			warnx("too many groups");
		/*
		 * Compress out duplicate.
		 */
		cr->cr_ngroups = ngroups - 1;
		cr->cr_groups[0] = groups[0];
		for (cnt = 2; cnt < ngroups; cnt++)
			cr->cr_groups[cnt - 1] = groups[cnt];
		return;
	}
	/*
	 * Explicit credential specified as a colon separated list:
	 *	uid:gid:gid:...
	 */
	if (pw != NULL)
		cr->cr_uid = pw->pw_uid;
	else if (isdigit(*name) || *name == '-')
		cr->cr_uid = atoi(name);
	else {
		warnx("unknown user: %s", name);
		return;
	}
	cr->cr_ngroups = 0;
	while (names != NULL && *names != '\0' && cr->cr_ngroups < XU_NGROUPS) {
		name = strsep(&names, ":");
		if (isdigit(*name) || *name == '-') {
			cr->cr_groups[cr->cr_ngroups++] = atoi(name);
		} else {
			if ((gr = getgrnam(name)) == NULL) {
				warnx("unknown group: %s", name);
				continue;
			}
			cr->cr_groups[cr->cr_ngroups++] = gr->gr_gid;
		}
	}
	if (names != NULL && *names != '\0' && cr->cr_ngroups == XU_NGROUPS)
		warnx("too many groups");
}

/*
 * Pare the second field[s] of an export line, which is a set
 * of options.  Some options are related to mountd's actions,
 * some are related to mountd's behaviour, some are for the kernel.
 * (mountd's go into *opts, kernel goes into args->ex_flags.)
 */
static char *
parse_opts(char *line, int *opts, struct export_args *args)
{
	*opts = 0;
	memset(args, 0, sizeof(*args));
	char *retval = line;

	if (*line != '-') {
		// Not an option
		return line;
	}
	
	while (retval && *retval == '-') {
		char *opt;
		char *optarg = NULL;
		struct export_options *optptr = export_options;
		int found = 0;
		
		if (strncmp(retval, "-net", 4) == 0 ||
		    strncmp(retval, "-mask", 5) == 0)
			break;
		opt = strsep_quote(&retval, " \t\n");
		if (opt == NULL)
			break;

		if (strchr(opt, '=')) {
			optarg = opt;
			opt = strsep_quote(&optarg, "=");
		}
		// sigh.  THis is wrong.  It snarfs up -network
		for (optptr = export_options; optptr->name; optptr++) {
			if (strcmp(opt, optptr->name) == 0) {
				found = 1;
				if (debug) {
					fprintf(stderr, "Found option %s\n", optptr->name);
					if (optarg)
						fprintf(stderr, "\targument = %s\n", optarg);
				}
				switch (optptr->type) {
				case OPT_MNT:
					args->ex_flags |= optptr->value;
					break;
				case OPT_MOUNTD:
					*opts |= optptr->value;
					break;
				case OPT_INDEX:
					if (optarg == NULL)
						warnx("-index requires argument");
					else
						args->ex_indexfile = strdup(optarg);
					break;
				case OPT_CRED:
					*opts |= optptr->value;
					parsecred(optarg, &args->ex_anon);
					break;
				case OPT_SEC:
					break;
				default:
					warnx("Unknown option type");
					break;
				}
				break;
			}
		}
		if (found == 0) {
			// Not an export option
			break;
		}
	}
	return retval;
}


static void
print_export_list(struct export_network_list *list)
{
	size_t indx;
	
	if (list == NULL) {
		printf("No network entries\n");
		return;
	}
	printf("%zd entries:\n", list->count);
	for (indx = 0; indx < list->count; indx++) {
		struct network_entry *entry = &list->entries[indx];
		struct sockaddr *sap = entry->network;
		char name[256] = { 0 };
		if (getnameinfo(sap, sap->sa_len, name, sizeof(name), NULL, 0, NI_NUMERICHOST) != 0) {
			strcpy(name, "<unknown>");
		}
		printf("\t%s", name);
		if (entry->mask) {
			printf("/%zd", netmask_to_masklen(entry->mask));
		}
		printf("\n");
	}
	return;
}
/*
 * Add the given host to the list.
 * Don't add it if it is already in the list.
 * Returns 0 on success, an errno on failure.
 */
static int
add_network_entry(struct export_network_list *list, struct sockaddr *sap, size_t masklen)
{
	struct network_entry *tmp;
	size_t indx;
	char name[255];
	struct sockaddr *mask = NULL;
	int retval = 0;
	
	if (debug)
		warnx("add_network_entry(%p, %p, %zd)", list, sap, masklen);

	if (list == NULL) {
		return EFAULT;
	}
	
	if (debug) {
		if (getnameinfo(sap, sap->sa_len, name, sizeof(name), NULL, 0, NI_NUMERICHOST) != 0) {
			strcpy(name, "<unknown>");
		}
	}
	if (masklen) {
		mask = malloc(sap->sa_len);
		if (mask == NULL) {
			return ENOMEM;
		}
		// Convert masklen to sockaddr
		memset(mask, 0, sap->sa_len);
		mask->sa_family = sap->sa_family;
		mask->sa_len = sap->sa_len;
		if (make_netmask((void*)mask, masklen) == -1) {
			if (debug || verbose)
				warnc(EINVAL, "Cannot make netmask with %zd", masklen);
			retval = EINVAL;
			goto done;
		}
	}
	for (indx = 0; indx < list->count; indx++) {
		if (((mask == 0 && list->entries[indx].mask == NULL) ||
		     (memcmp(mask, list->entries[indx].mask, sap->sa_len) == 0)) &&
		    memcmp(sap, list->entries[indx].network, sap->sa_len) == 0) {
			// Entry already in the list, so do nothing
			if (debug) {
				warnx("Redundant entry (%s) in network list, not adding", name);
			}
			retval = 0;
			goto done;
		}
	}

	// If we're here, then we need to add the entry to the list
	tmp = realloc(list->entries, sizeof(*tmp) * (indx + 1));
	if (tmp == NULL) {
		return ENOMEM;
	}
	tmp[indx].network = malloc(sap->sa_len);
	if (tmp[indx].network == NULL) {
		retval = ENOMEM;
		goto done;
	}
	memcpy(tmp[indx].network, sap, sap->sa_len);
	tmp[indx].mask = mask;
	list->entries = tmp;
	list->count++;
	if (debug) {
		warnx("Added entry %s/%zd to network list", name, masklen);
	}

done:
	if (retval && mask)
		free(mask);
	return retval;
}



/*
 * The last section of an export line consists of networks, hosts, and
 * netgroups.  I don't know anything about the latter, so I'm ignoring that
 * for now.
 * A host may be specified as a hostname, or an address (ipV4 or ipV6).
 * A network requires "-network="; it SHOULD specify a network mask, but
 * that may be optionally specified via a "-mask=".  That's stupid.
 */
static char *
parse_hosts(char *line, struct export_network_list *networks)
{
	int net = 0, mask = 0;
	char *retval = line;
	char *entry;
	struct sockaddr *network_net = NULL;
	struct export_network_list list = { 0 };
	
	if (line == NULL || *line == 0)
		return NULL;

	if (networks == NULL) {
		networks = &list;
	}
	
	while (retval && *retval != 0) {
		char *optarg;
		entry = strsep(&retval, " \t\n");	// Deliberately strsep here
		optarg = entry;
		entry = strsep(&optarg, "=");
		if (entry == NULL)
			abort();

		if (strcmp(entry, "-network") == 0) {
			if (optarg == NULL) {
				warnx("Error:  -network must specify network");
				continue;
			}
			if (strchr(optarg, '/')) {
				// We've got CIDR
				char *cidr = strchr(optarg, '/');
				unsigned long masklen;
				char *tmp;
				struct addrinfo *ai, hints = { 0 };
				*cidr = 0;
				cidr++;
				masklen = strtoul(cidr, &tmp, 0);
				if (masklen == ULONG_MAX && errno != 0) {
					warn("Could not parse %s as number", cidr);
					continue;
				}
				hints.ai_flags = AI_NUMERICHOST;
				hints.ai_family = AF_UNSPEC;
				if (getaddrinfo(optarg, NULL, &hints, &ai) == 0) {
					struct sockaddr *t_addr, *t_mask;
					// Need to do something now
					// Should only be one AI in the link, so that simplifies things.
					add_network_entry(networks, ai->ai_addr, masklen);
					freeaddrinfo(ai);
				} else {
					warn("Could not convert %s into an addrinfo", optarg);
				}
			} else {
				// Just a network.  Hopefully.
				// But we need to see if the next entry is -mask before we can
				// do anything.
				struct addrinfo *ai, hints = { 0 };
				hints.ai_flags = AI_NUMERICHOST;
				hints.ai_family = AF_UNSPEC;
				if (getaddrinfo(optarg, NULL, &hints, &ai) == 0) {
					network_net = malloc(ai->ai_addrlen);
					if (network_net == NULL)
						abort();
					memcpy(network_net, ai->ai_addr, ai->ai_addrlen);
					freeaddrinfo(ai);
				} else {
					warn("Could not convert %s into an addrinfo", optarg);
				}
			}
		} else if (strcmp(entry, "-mask") == 0) {
			if (optarg == NULL) {
				warnx("Error:  -mask must specify mask");
				free(network_net);
				network_net = NULL;
				continue;
			}
			if (network_net == NULL) {
				warnx("Error:  cannot specify -mask without -network");
				continue;
			} else {
				struct addrinfo *ai, hints = { 0 };
				hints.ai_flags = AI_NUMERICHOST;
				hints.ai_family = AF_UNSPEC;
				if (getaddrinfo(optarg, NULL, &hints, &ai) == 0) {
					int masklen = 0;
					masklen = netmask_to_masklen(ai->ai_addr);
					if (masklen == -1) {
						warnx("Invalid network mask %s", optarg);
					} else {
						add_network_entry(networks, network_net, masklen);
					}
					freeaddrinfo(ai);
				} else {
					warn("Could not convert %s into an addrinfo", optarg);
				}
				free(network_net);
				network_net = NULL;
			}
		} else {
			// A named host, or a numeric address
			char *tmp;
			struct addrinfo *ai, hints = { 0 };

			// First, some cleanup
			if (network_net) {
				add_network_entry(networks, network_net, 0);
				free(network_net);
				network_net = NULL;
			}
			hints.ai_family = AF_UNSPEC;
			hints.ai_flags |= AI_PASSIVE;
			if (getaddrinfo(entry, NULL, &hints, &ai) == 0) {
				struct addrinfo *tai;
				struct sockaddr *t_addr, *t_mask;
				// Need to do something now
				// That "something" involves taking the addrinfo chain
				// and converting them into the right data.  masklen
				// is going to be the size of the sockaddr * NBBY.
				for (tai = ai;
				     tai;
				     tai = tai->ai_next) {
					int rv;

					switch (tai->ai_family) {
					case AF_INET:
					case AF_INET6:
						break;
					default:
						warnx("Unknown family %d, ignoring", tai->ai_family);
						continue;
					}
					rv = add_network_entry(networks, tai->ai_addr, 0);
				}
				freeaddrinfo(ai);
			} else {
				warn("Could not convert %s into an addrinfo", optarg);
			}
		}
	}
	if (verbose)
		print_export_list(networks);
	
	return retval;
}


/*
 * Parse the first field[s] of an export line, which is
 * all about exported filesystem objects.
 */
static char *
parse_mounts(char *line, size_t *count, struct export_mount **mounts)
{
	char *retval = line;
	char *cp;
	struct export_mount *mount_list = NULL;
	size_t mount_count = 0;
	
	if (count == NULL || mounts == NULL) {
		warnx("parse_mounts called with invalid parameters");
		errno = EINVAL;
		return NULL;
	}
	
	if (strncmp(retval, "V4:/", 4) == 0) {
		// V4 root directory
		cp = strsep_quote(&retval, " \t\n");
	} else {
		while (retval && *retval == '/') {
			// Got a mount point!
			char *exp_name = NULL, *path_name = NULL;
			cp = strsep_quote(&retval, " \t\n");
			if (strchr(cp, '=')) {
				path_name = strdup(strsep_quote(&cp, "="));
				exp_name = strdup(cp);
			} else {
				path_name = strdup(cp);
				exp_name = strdup(path_name);
			}
			if (debug)
				fprintf(stderr, "%s(%d):  path %s, exported as %s\n", __FUNCTION__, __LINE__, path_name, exp_name);
			mount_list = realloc(mount_list, sizeof(*mount_list) * (mount_count + 1));
			mount_list[mount_count].export_name = exp_name;
			mount_list[mount_count].real_name = path_name;	// Should we realpath it?
			mount_count++;
		}
	}
	if (mount_list) {
		*mounts = mount_list;
		*count = mount_count;
	}

	// Either the next field, or NULL
	return retval;
}

static void
parse_line(char *exp_line)
{
	size_t count = 0, i;
	struct export_mount *exports = NULL;
	struct export_network_list nets = { 0 };
	int options = 0;
	struct export_args eargs = {
		.ex_anon.cr_uid = -2,
		.ex_anon.cr_ngroups = 1,
		.ex_anon.cr_groups[0] = -2,
	};

	exp_line = parse_mounts(exp_line, &count, &exports);

	if (count == 0) {
		fprintf(stderr, "Invalid exports line, ignoring\n");
		return;
	}
	
	if (exp_line) {
		exp_line = parse_opts(exp_line, &options, &eargs);
	}
	
	if (exp_line) {
		exp_line = parse_hosts(exp_line, &nets);
	}
	
	/*
	 * Now we've got all the mounts and options for this line.
	 * Iterate over the mounts.
	 */
	for (i = 0; i < count; i++) {
		struct export_entry *entry;
		int rv;
		
		if (verbose) {
			printf("Export %s as %s", exports[i].real_name, exports[i].export_name);
			if (nets.count == 0)
				printf(" (DEFAULT ENTRY)");
			printf("\n");
		}
		/*
		 * This gives us an entry with the filesystem to be exported,
		 * and all the flags and options we set up.
		 */
		entry = CreateExportEntry(exports[i].real_name,
					  options,
					  &eargs,
					  nets.count,
					  nets.entries);
		rv = AddEntryToTree(exports[i].export_name, entry);
		if (debug && verbose)
			PrintTree();
	}
	
}

void
read_export_file(FILE *fp)
{
	char *line;

	while ((line = get_line(fp)) != NULL) {
		if (debug)
			fprintf(stderr, "line = %s\n", line);
		if (*line == '#') {
			if (debug) {
				fprintf(stderr, "Ignoring comment line\n");
			}
		} else {
			parse_line(line);
		}
		free(line);
	}
	
}

