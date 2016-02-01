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
#ifndef _MOUNTD_H
# define _MOUNTD_H

# include <sys/socket.h>
# include <sys/mount.h>
/*
 * This defines an exported network or host.
 * This maps very closely to what the kernel wants
 * in export_args.
 */
struct network_entry {
	struct sockaddr	*network;
	struct sockaddr	*mask;	// may be NULL, indicating a host
};

/*
 * The per-path results of an export(5) line.
 * This will be used to map a mount request to the actual
 * filesystem.  (For that mapping, we go first from the mount
 * request path, then use the IP address to find which export_entry
 * matches it, and then do magic to get the filehandle from
 * the export_path combined with the mount request.)
 */
struct export_entry {
	char	*export_path;	// The path/FS being exported
	int	export_flags;	// Used by mountd
	struct export_args	args;	// Used by the kernel
	size_t	network_count;
	struct network_entry entries[0];
};

/*
 * The list of exports for a given exported name.  If no
 * export name is given, it defaults to the path being exported.
 * So for "/mnt/tank/home -alldirs 10.0.0.0/24", this would
 * result in export_node->export_name being "/mnt/tank/home", and
 * the appropriate exports->export_path being the same.  But with
 * "/mnt/tank/home=/home -alldirs 10.0.0.0/24", then export_node
 * would have "/home", while the export_entry would have "/mnt/tank/home".
 */
struct export_node {
	char	*export_name;	// The name which is exported
	struct export_entry	default_export;	// This will have network_count of 0
	size_t	export_count;
	struct export_entry *exports[0];	// export_count of them
};

struct export_tree {
	struct export_node	*node;	// This contains the name of the node
	struct export_tree	*parent;	// Parent.  NULL for root, of course
	struct export_tree	*left, *right;
};

/*
 * Configuration structure.  This is mainly to get all of the
 * options in one place.
 */
struct server_config {
	int force_v2;
	int resvport_only;
	int dir_only;
	int dolog;
	int have_v6;
	in_port_t bind_port;
	size_t naddrs;
	char **bind_addrs;
};

/*
 * Options used by mountd.
 */
# define OPT_MAP_ROOT	0x0001
# define OPT_MAP_ALL	0x0002
# define OPT_SECLIST	0x0004
# define OPT_ALLDIRS	0x0008
# define OPT_INDEXFILE	0x0010
# define OPT_QUIET	0x0020

/*
 * Values used by the network functions.
 */
# define NET_MATCH_NONE	(-1)
# define NET_MATCH_HOST	(SOCK_MAXADDRLEN * NBBY)

# define NODE_HAS_DEFAULT(np) ((np) && (np)->default_export.export_path != NULL)

# define _PATH_RMOUNTLIST	"/var/db/mountdtab"

extern int debug, verbose;
extern struct server_config server_config;

extern void out_of_mem(void);

// Network support routines
extern uint8_t *sa_rawaddr(struct sockaddr *, int *);
extern int make_netmask(struct sockaddr_storage *, int);
extern int netmask_to_masklen(struct sockaddr *);
extern int network_compare(struct network_entry *, struct sockaddr *);
extern int check_ipv6(void);

// Tree-related routines
extern struct export_entry *CreateExportEntry(const char *,
					      int,
					      struct export_args *,
					      size_t,
					      struct network_entry *);

extern int AddEntryToTree(const char *, struct export_entry *);

extern void PrintTree(void);
extern void ListExports(void);

extern void PrintExportEntry(struct export_entry *, const char *);

extern void IterateTree(int (^)(struct export_node *));

extern struct export_tree *FindNodeBestName(const char *);
extern struct export_entry *FindBestExportForAddress(const char *, struct sockaddr *, char **);

extern void ReleaseTree(void);

// Parsing
extern void read_export_file(FILE *);

// Mount support
extern void UnexportFilesystems(void);
extern void ExportFilesystems(void);

// RPC support
extern void init_rpc(void);
extern void service_rpc(void);
extern void stop_rpc(void);

#endif /* _MOUNTD_H */
