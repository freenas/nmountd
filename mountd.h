#ifndef _MOUNTD_H
# define _MOUNTD_H

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
	struct export_entry exports[0];	// export_count of them
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

#endif /* _MOUNTD_H */
