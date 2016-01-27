#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <err.h>
#include <errno.h>
#include <syslog.h>

#include <netdb.h>

#include "mountd.h"

#define NODE_SIZE(node) (sizeof(struct export_node) + ((node)->export_count * sizeof(struct export_entry*)))
#define ENTRY_SIZE(entry) (sizeof(struct export_entry) + ((entry)->network_count * sizeof(struct network_entry)))

/*
 * Create an export entry; this will be used to
 * help populate the node for the export path.
 */
struct export_entry *
CreateExportEntry(const char *path,
		  int flags,
		  struct export_args *kargs,
		  size_t network_count,
		  struct network_entry *entries)
{
	struct export_entry *retval = NULL;

	retval = calloc(1, sizeof(struct export_entry) + network_count * sizeof(*entries));
	if (retval) {
		retval->export_path = strdup(path);
		retval->export_flags = flags;
		retval->args = *kargs;
		if (retval->args.ex_indexfile)
			retval->args.ex_indexfile = strdup(retval->args.ex_indexfile);
		retval->network_count = network_count;
		memcpy(retval->entries, entries, network_count * sizeof(*entries));
	}
	return retval;
}

/*
 * Release the memory for an export entry.
 * Only the indexfile (if set) in export_args is released.
 */
void
FreeExportEntry(struct export_entry *entry)
{
	if (entry) {
		if (entry->export_path)
			free(entry->export_path);
#if 0
		if (entry->args.ex_addr)
			free(entry->args.ex_addr);
		if (entry->args.ex_mask)
			free(entry->args.ex_mask);
#endif
		if (entry->args.ex_indexfile)
			free(entry->args.ex_indexfile);
		free(entry);
	}
	return;
}


static struct export_tree *root;

/*
 * Return the node with the best match for
 * the given name.
 */
struct export_tree *
FindNodeBestName(const char *name)
{
	struct export_tree *retval = NULL;
	int rv;
	
	if (root == NULL)
		return NULL;
	retval = root;

#ifdef TREE_DEBUG
	fprintf(stderr, "Looking for %s\n", name);
#endif
	do {
		rv = strcmp(retval->node->export_name, name);
#ifdef TREE_DEBUG
		fprintf(stderr, "\t%s compared to %s = %d\n", retval->node->export_name, name, rv);
#endif
		if (rv == 0) 
			return retval;
		if (rv > 0) {
			// See if there is a child to the left
			if (retval->left) {
				retval = retval->left;
			} else {
				return retval;
			}
		} else if (rv < 0) {
			// See if there is a child to the right
			if (retval->right) {
				retval = retval->right;
			} else {
				return retval;
			}
		}
	} while (retval);
	return retval;
}

/*
 * Add the specified entry to the btree, using the given export name.
 * If there is no node matching the name (which must be an exact match),
 * then one is created, and inserted into the tree.
 *
 * Returns 0 on success, an errno on error.
 * Possible errors are:
 * ENOMEM -- no memory for allocation
 * EEXIST -- an entry for name already exists, with a default value,
 * and entry also specifies a default value.
 */

static struct export_node *
AddEntryToNode(struct export_node *node, struct export_entry *entry)
{
	struct export_node *retval = NULL;

	/*
	 * If entry->network_count is 0, this is a default entry.
	 * We need to see if there is already a default entry.
	 */
	if (entry->network_count == 0) {
		// Default entry, but let's see if the node already has one
		if (node->default_export.export_path) {
			errno = EEXIST;
		} else {
			node->default_export = *entry;
			retval = node;
		}
		goto done;
	}
	retval = realloc(node, NODE_SIZE(node) + ENTRY_SIZE(entry));
	if (retval == NULL) {
		errno = ENOMEM;
		goto done;
	}
	node = retval;
	node->exports[node->export_count] = entry;
	node->export_count++;
done:
	return retval;
	
}

/*
 * Used to create a node.  Caller must handle parent, left, and right
 * as appropriate.
 */
static struct export_node *
CreateNode(const char *name, struct export_entry *entry)
{
	struct export_node *retval = NULL;

	retval = calloc(1, sizeof(*retval) + sizeof(*entry) * entry->network_count);
	if (retval == NULL)
		return NULL;
	memset(retval, 0, sizeof(*retval));
	retval->export_name = strdup(name);
	if (retval->export_name == NULL) {
		free(retval);
		return NULL;
	}
	if (entry->network_count == 0) {
		retval->default_export = *entry;
		retval->export_count = 0;
		// Default entry
	} else {
		retval->export_count = 1;
		retval->exports[0] = entry;
	}
	return retval;
}

void
PrintExportEntry(struct export_entry *entry, const char *prefix)
{
	printf("%sPath %s\n", prefix, entry->export_path);
	printf("%sExport Flags %#x\n", prefix, entry->export_flags);
	printf("%sKernel Args:\n", prefix);
	printf("%s\tex_flags %#x\n", prefix, entry->args.ex_flags);
	printf("%s\tex_root %d\n", prefix, entry->args.ex_root);
	printf("%s\tex_anon = { %d, %d, ... }\n", prefix, entry->args.ex_anon.cr_uid, entry->args.ex_anon.cr_gid);
	if (entry->args.ex_addr) {
		char host[255];
		if (getnameinfo(entry->args.ex_addr, entry->args.ex_addr->sa_len,
				host, sizeof(host), NULL, 0, NI_NUMERICHOST) == -1) {
			strcpy(host, "<unknown>");
		}
		printf("%s\tex_addr %s", prefix, host);
		if (entry->args.ex_mask) {
			printf("/%d", netmask_to_masklen(entry->args.ex_mask));
		}
		printf("\n");
	}
	if (entry->network_count) {
		size_t i;
		struct network_entry *ep = entry->entries;
		printf("%sNetwork entries:\n", prefix);
		for (i = 0; i < entry->network_count; i++) {
			char host[255];
			if (ep[i].network == NULL) {
				warnx("For some reason, entry %zd is NULL?!?!", i);
				continue;
			}
			if (getnameinfo(ep[i].network, ep[i].network->sa_len,
					host, sizeof(host), NULL, 0, NI_NUMERICHOST) == -1) {
				strcpy(host, "<unknown>");
			}
			printf("%s\t%s", prefix, host);
			if (ep[i].mask) {
				printf("/%d", netmask_to_masklen(ep[i].mask));
			}
			printf("\n");
		}
	}
	return;
}
static void
PrintNode(struct export_node *node)
{
	// Prints intended by one tab
	if (node->default_export.export_path) {
		PrintExportEntry(&node->default_export, "\tDefault ");
		
	}
	if (node->export_count) {
		size_t indx;
		struct export_entry **eep = node->exports;
		
		for (indx = 0; indx < node->export_count; indx++) {
			char *prefix;
			asprintf(&prefix, "\tExport entry %zd: ", indx);
			PrintExportEntry(eep[indx], prefix);
			free(prefix);
		}
	}
	return;
			
}

static void
PrintTreeNode(struct export_tree *tree)
{
	if (tree->node) {
		printf("Node:  %s\n", tree->node->export_name);
		PrintNode(tree->node);
	}
	if (tree->left)
		PrintTreeNode(tree->left);
	if (tree->right)
		PrintTreeNode(tree->right);
}

void
PrintTree(void)
{
	PrintTreeNode(root);
}

int
AddEntryToTree(const char *name, struct export_entry *entry)
{
	int rv = 0;
	struct export_node *node;
	
	if (root == NULL) {
		// Easy enough, we're adding it here
		root = calloc(1, sizeof(*root));
		if (root == NULL) {
			rv = ENOMEM;
			goto done;
		}
		node = CreateNode(name, entry);
		if (node == NULL) {
			free(root);
			root = NULL;
			rv = ENOMEM;
			goto done;
		}
		root->node = node;
		rv = 0;
		goto done;
	} else {
		struct export_tree *tree;

		tree = FindNodeBestName(name);
		if (tree == NULL) {
			abort();
		} else {
			int cmp;
			/*
			 * Okay, tree either points to the node we want,
			 * or the one with the best name.
			 */
			cmp = strcmp(tree->node->export_name, name);
#ifdef TREE_DEBUG
			fprintf(stderr, "* * * %s compare %s:  %d\n", tree->node->export_name, name, cmp);
#endif
			if (cmp == 0) {
				/*
				 * Great, got an exact match.
				 * That means we need to add entry to the node.
				 */
				struct export_node *tmp = AddEntryToNode(tree->node, entry);
				if (tmp == NULL) {
					if (errno == EEXIST) {
						warnx("Could not add %s (default entry already exists)", entry->export_path);
					} else {
						warn("Could not add %s", entry->export_path);
					}
					rv = ENOMEM;
					goto done;
				}
				tree->node = tmp;
#ifdef TREE_DEBUG
				printf("Added another entry to %s\n", tree->node->export_name);
#endif
			} else {
				// We have to create a node
				struct export_node *node = CreateNode(name, entry);
				if (node == NULL) {
					rv = ENOMEM;
					goto done;
				}
				if (cmp > 0) {
					/*
					 * The new name is lexically greater than the current, so
					 * add it to left.
					 */
					struct export_tree *parent = tree->parent;
					struct export_tree *tmp = tree->left;
					struct export_tree *new_tree = calloc(1, sizeof(*new_tree));
					if (new_tree == NULL) {
						rv = ENOMEM;
						free(node);	// memory leak
						goto done;
					}
					new_tree->node = node;
					new_tree->left = tree->left;
					if (tree->left)
						tree->left->parent = new_tree;
					new_tree->parent = tree;
					tree->left = new_tree;
#ifdef TREE_DEBUG
					printf("Added %s as entry to left of %s\n", name, tree->node->export_name);
#endif
				} else if (cmp < 0) {
					/*
					 * The name is lexically less than the current, so
					 * add it to right
					 */
					struct export_tree *parent = tree->parent;
					struct export_tree *tmp = tree->right;
					struct export_tree *new_tree = calloc(1, sizeof(*new_tree));
					if (new_tree == NULL) {
						rv = ENOMEM;
						free(node);	// memory leak
						goto done;
					}
					new_tree->node = node;
					new_tree->right = tree->right;
					if (tree->right)
						tree->right->parent = new_tree;
					new_tree->parent = tree;
					tree->right = new_tree;
#ifdef TREE_DEBUG
					printf("Added %s as entry to right of %s\n", name, tree->node->export_name);
#endif
				}
			}
		}
	}
done:
	return rv;
}
