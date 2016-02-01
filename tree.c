/*
 * Copyright (c) 2016, iXsystems, Inc.
 * All rights reserved.
 *
 * 1.  Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 2.  Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * 3.  Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * Neither the name of py-bsd nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
	
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

static struct export_tree *root;

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
static void
FreeExportEntry(struct export_entry *entry)
{
	if (entry) {
		size_t indx;
		
		if (entry->export_path)
			free(entry->export_path);
		if (entry->args.ex_indexfile)
			free(entry->args.ex_indexfile);
		for (indx = 0; indx < entry->network_count; indx++) {
			struct network_entry *nep = &entry->entries[indx];
			if (nep->network)
				free(nep->network);
			if (nep->mask)
				free(nep->mask);
		}
		free(entry);
	}
	return;
}

static void
FreeExportNode(struct export_node *node)
{
	size_t indx;
	
	free(node->export_name);
	if (node->default_export.export_path)
		free(node->default_export.export_path);
	if (node->default_export.args.ex_indexfile)
		free(node->default_export.args.ex_indexfile);

	for (indx = 0; indx < node->export_count; indx++) {
		FreeExportEntry(node->exports[indx]);
	}
	free(node);
	return;
}

static void
FreeTree(struct export_tree *tree)
{
	if (tree) {
		if (tree->node) {
			FreeExportNode(tree->node);
		}
		FreeTree(tree->left);
		FreeTree(tree->right);
		free(tree);
	}
}

void
ReleaseTree(void)
{
	FreeTree(root);
	return;
}

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
 * Return the export_entry that best matches
 * the given name and ip address.
 *
 * Returns NULL if it can't find a match.
 *
 * If export_name is non-NULL, it will be set to
 * point to the appropriate exported name.
 *
 * Okay, "best" here can go one of two ways:
 * First, we can look for the export_node with
 * the longest match for the given name, and then
 * find the export_entry that best matches the address,
 * and return that.  (This may be the default export,
 * if there is one, if the address doesn't match any
 * of the networks.)
 *
 * The other way to find the "best" would be to find
 * the node that has the best match for the address,
 * then the one with the longest name match.
 *
 * I'm going with the first way for now.
 */
struct export_entry *
FindBestExportForAddress(const char *requested, struct sockaddr *sap, char **export_name)
{
	struct export_entry *retval = NULL;
	struct export_tree *best_tree_node;
	struct export_node *best_node;
	size_t i;
	int best_match = NET_MATCH_NONE;
	
	best_tree_node = FindNodeBestName(requested);
	if (best_tree_node == NULL)
		return NULL;

	best_node = best_tree_node->node;
	/*
	 * Because of how FindNodeBestName works, we need to make sure
	 * that best_node->export_name is a subset of requested.
	 */
	if (strncmp(best_node->export_name, requested,
		    strlen(best_node->export_name)) != 0)
		return NULL;
	
	for (i = 0; i < best_node->export_count; i++) {
		size_t network_indx;
		struct export_entry *ep = best_node->exports[i];

		for (network_indx = 0;
		     network_indx < ep->network_count;
		     network_indx++) {
			int cmp = network_compare(ep->entries+network_indx,
						  sap);
			if (cmp > best_match) {
				retval = ep;
				best_match = cmp;
			}
		}
	}
	if (retval == NULL && NODE_HAS_DEFAULT(best_node)) {
		retval = &best_node->default_export;
	}
	if (retval && export_name)
		*export_name = best_node->export_name;
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
	size_t indx;
	
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

	/*
	 * Next thing we can do is see if this is just adding another
	 * network_entry to the export_entry list.  To do that, we check
	 * all of the export entries, and compare the values.
	 * This also will check to see if the network/mask is already on
	 * the list, and do nothing in that case.
	 */
	for (indx = 0; indx < node->export_count; indx++) {
		struct export_entry *ep = node->exports[indx];

		if (strcmp(entry->export_path, ep->export_path) == 0 &&
		    entry->export_flags == ep->export_flags &&
		    entry->args.ex_flags == ep->args.ex_flags &&
		    entry->args.ex_root == ep->args.ex_root &&
		    memcmp(&entry->args.ex_anon, &ep->args.ex_anon, sizeof(ep->args.ex_anon)) == 0) {
			/*
			 * We want to merge entry, into ep.
			 * To do this, we iterate through entry->exports, and compare each
			 * entry to ep->exports.  Note that when we realloc, we need
			 * change node->exports[indx]
			 *
			 * You know, for now, let's just add them all.
			 */
			size_t new_size;
			size_t new_index;
			
			new_size = ENTRY_SIZE(entry) + entry->network_count * sizeof(struct network_entry);
			ep = realloc(ep, new_size);
			if (ep == NULL) {
				warn("Could not add new entries to node, sorry");
				out_of_mem();
			}
			node->exports[indx] = ep;
			for (new_index = 0;
			     new_index < entry->network_count;
			     new_index++) {
				ep->entries[ep->network_count++] = entry->entries[new_index];
			}
			free(entry);
			return node;
		}
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

static int
tree_walker(struct export_tree *tree,
	    int (^handler)(struct export_node *))
{
	int rv;

	rv = (handler)(tree->node);
	if (rv != 0)
		return rv;

	if (tree->left) {
		rv = tree_walker(tree->left, handler);
		if (rv)
			return rv;
	}
	if (tree->right) {
		rv = tree_walker(tree->right, handler);
		if (rv)
			return rv;
	}
	return 0;
}

void
PrintTree(void)
{
	tree_walker(root, ^(struct export_node *node) {
			printf("Node:  %s\n", node->export_name);
			PrintNode(node);
			return 0;
		});
}

void
IterateTree(int (^handler)(struct export_node *))
{
	tree_walker(root, handler);
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

void
ListExports(void)
{
	// Iterate over the tree
	IterateTree(^(struct export_node *node) {
			size_t indx;
			if (node->default_export.export_path) {
				printf("%s=%s\tEveryone\n", node->default_export.export_path, node->export_name);
			}
			for (indx = 0; indx < node->export_count; indx++) {
				struct export_entry *ep = node->exports[indx];
				if (ep->network_count > 0) {
					size_t net_indx;
					printf("%s=%s", ep->export_path, node->export_name);
					for (net_indx = 0; net_indx < ep->network_count; net_indx++) {
						struct network_entry *np = &ep->entries[net_indx];
						struct sockaddr *sap = np->network;
						char host[255];
						if (getnameinfo(sap, sap->sa_len,
							       host, sizeof(host),
							       NULL, 0, NI_NUMERICHOST) == -1) {
							strcpy("<unknown>", host);
						}
						printf(" %s", host);
						if (np->mask) {
							printf("/%d", netmask_to_masklen(np->mask));
						}
					}
					printf("\n");
				}
			}
			return 0;
		});
	return;
}
