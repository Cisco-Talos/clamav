/*
 *  Copyright (C) 2015-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 *  Authors: Mickey Sola
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#if defined(FANOTIFY)
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>

#include <sys/fanotify.h>

#include "onaccess_fan.h"
#include "onaccess_hash.h"
#include "onaccess_ddd.h"

#include "libclamav/clamav.h"
#include "libclamav/scanners.h"
#include "libclamav/str.h"

#include "shared/optparser.h"
#include "shared/output.h"

#include "server.h"
#include "others.h"
#include "scanner.h"
#include "priv_fts.h"

static struct onas_bucket *onas_bucket_init();
static void onas_free_bucket(struct onas_bucket *bckt);
static int onas_bucket_insert(struct onas_bucket *bckt, struct onas_element *elem);
static int onas_bucket_remove(struct onas_bucket *bckt, struct onas_element *elem);

static int onas_add_hashnode_child(struct onas_hnode *node, const char* dirname);

static struct onas_lnode *onas_listnode_init(void);

static struct onas_hnode *onas_hashnode_init(void);

static inline uint32_t onas_hshift(uint32_t hash) {

	hash = ~hash;

	hash += (hash << 15);
	hash ^= (hash >> 12);
	hash += (hash << 2);
	hash ^= (hash >> 4);
	hash += (hash << 3);
	hash += (hash << 11);
	hash ^= (hash >> 16);

	return hash;
}

static inline int onas_hash(const char* key, size_t keylen, uint32_t size) {

	uint32_t hash = 1;
	uint32_t i;

	for (i = 0; i < keylen; i++) {
		hash += key[i];
		hash = onas_hshift(hash);
	}

	return hash & (size - 1);
}

int onas_ht_init(struct onas_ht **ht, uint32_t size) {

	if (size == 0 || (size & (~size + 1)) != size) return CL_EARG;

	*ht = (struct onas_ht *) cli_malloc(sizeof(struct onas_ht));
	if (!(*ht)) return CL_EMEM;

	**ht = (struct onas_ht) {
		.htable = NULL,
		.size = size,
		.nbckts = 0,
	};

	if (!((*ht)->htable = (struct onas_bucket **) cli_calloc(size, sizeof(struct onas_bucket *)))) {
		onas_free_ht(*ht);
		return CL_EMEM;
	}

	return CL_SUCCESS;
}

void onas_free_ht(struct onas_ht *ht) {

	if (!ht || ht->size == 0) return;

	if (!ht->htable) {
		free(ht);
		return;
	}

	uint32_t i = 0;
	for (i = 0; i < ht->size; i++) {
		onas_free_bucket(ht->htable[i]);
		ht->htable[i] = NULL;
	}

	free(ht->htable);
	ht->htable = NULL;

	free(ht);

	return;
}

static struct onas_bucket *onas_bucket_init() {

	struct onas_bucket *bckt = (struct onas_bucket*) cli_malloc(sizeof(struct onas_bucket));
	if (!bckt) return NULL;

	*bckt = (struct onas_bucket) {
		.size = 0,
		.head = NULL,
		.tail = NULL
	};

	return bckt;
}

static void onas_free_bucket(struct onas_bucket *bckt) {

	if (!bckt) return;

	uint32_t i = 0;
	struct onas_element *curr = NULL;

	for (i = 0; i < bckt->size; i++) {
		curr = bckt->head;
		bckt->head = curr->next;
		onas_free_element(curr);
		curr = NULL;
	}

	free(bckt);

	return;
}

struct onas_element *onas_element_init(struct onas_hnode *value, const char *key, size_t klen) {

	struct onas_element *elem = (struct onas_element *) cli_malloc(sizeof(struct onas_element));
	if (!elem) return NULL;

	*elem = (struct onas_element) {
		.key = key,
		.klen = klen,
		.data = value,
		.next = NULL,
		.prev = NULL
	};

	return elem;
}

void onas_free_element(struct onas_element *elem) {

	if (!elem) return;

	onas_free_hashnode(elem->data);

	elem->prev = NULL;
	elem->next = NULL;

	free(elem);

	return;
}

int onas_ht_insert(struct onas_ht *ht, struct onas_element *elem) {

	if (!ht || !elem || !elem->key) return CL_ENULLARG;

	int idx = onas_hash(elem->key, elem->klen, ht->size);
	struct onas_bucket *bckt = ht->htable[idx];

	int ret = 0;
	uint32_t bsize = 0;

	if (bckt == NULL) {
		ht->htable[idx] = onas_bucket_init();
		bckt = ht->htable[idx];
	}

	bsize = bckt->size;
	ret = onas_bucket_insert(bckt, elem);

	if (ret == CL_SUCCESS)
		if (bsize < bckt->size)
			ht->nbckts++;

	return ret;
}

static int onas_bucket_insert(struct onas_bucket *bckt, struct onas_element *elem) {
	if (!bckt || !elem) return CL_ENULLARG;

	if (bckt->size == 0) {
		bckt->head = elem;
		bckt->tail = elem;
		elem->prev = NULL;
		elem->next = NULL;
		bckt->size++;
	} else {
		struct onas_element *btail = bckt->tail;

		btail->next = elem;
		elem->prev = btail;
		elem->next = NULL;
		bckt->tail = elem;
		bckt->size++;
	}

	return CL_SUCCESS;
}

/* Checks if key exists and optionally stores address to the element corresponding to the key within elem */
int onas_ht_get(struct onas_ht *ht, const char *key, size_t klen, struct onas_element **elem) {

	if (elem) *elem = NULL;

	if (!ht || !key || klen <= 0) return CL_ENULLARG;

	struct onas_bucket *bckt = ht->htable[onas_hash(key, klen, ht->size)];

	if (!bckt || bckt->size == 0) return CL_EARG;

	struct onas_element *curr = bckt->head;

	while (curr && strcmp(curr->key, key)) {
		curr = curr->next;
	}
	
	if (!curr) return CL_EARG;

	if (elem) *elem = curr;

	return CL_SUCCESS;
}

/* Removes the element corresponding to key from the hashtable and optionally returns a pointer to the removed element. */
int onas_ht_remove(struct onas_ht *ht, const char* key, size_t klen, struct onas_element **relem) {
	if (!ht || !key || klen <= 0) return CL_ENULLARG;

	struct onas_bucket *bckt = ht->htable[onas_hash(key, klen, ht->size)];

	if (!bckt) return CL_EARG;

	struct onas_element *elem = NULL;
	onas_ht_get(ht, key, klen, &elem);

	if (!elem) return CL_EARG;

	int ret = onas_bucket_remove(bckt, elem);

	if (relem) *relem = elem;

	return ret;
}

static int onas_bucket_remove(struct onas_bucket *bckt, struct onas_element *elem) {
	if (!bckt || !elem) return CL_ENULLARG;

	struct onas_element *curr = bckt->head;

	while (curr && curr != elem) {
		curr = curr->next;
	}

	if (!curr) return CL_EARG;

	if (bckt->head == elem) {
		bckt->head = elem->next;
		if (bckt->head) bckt->head->prev = NULL;

		elem->next = NULL;
	} else if (bckt->tail == elem) {
		bckt->tail = elem->prev;
		if (bckt->tail) bckt->tail->next = NULL;

		elem->prev = NULL;
	} else {
		struct onas_element *tmp = NULL;

		tmp = elem->prev;
		if (tmp) {
			tmp->next = elem->next;
			tmp = elem->next;
			tmp->prev = elem->prev;
		}

		elem->prev = NULL;
		elem->next = NULL;
	}

	bckt->size--;

	return CL_SUCCESS;
}


/* Dealing with hash nodes and list nodes */

/* Function to initialize hashnode. */
static struct onas_hnode *onas_hashnode_init(void) {
	struct onas_hnode *hnode = NULL;
	if(!(hnode = (struct onas_hnode *) cli_malloc(sizeof(struct onas_hnode)))) {
		return NULL;
	}

	*hnode = (struct onas_hnode) {
		.pathlen = 0,
		.pathname = NULL,
		.prnt_pathlen = 0,
		.prnt_pathname = NULL,
		.childhead = NULL,
		.childtail = NULL,
		.wd = 0,
		.watched = 0
	};

	if (!(hnode->childhead = (struct onas_lnode *) onas_listnode_init())) {
		onas_free_hashnode(hnode);
		return NULL;
	}

	if (!(hnode->childtail = (struct onas_lnode *) onas_listnode_init())) {
		onas_free_hashnode(hnode);
		return NULL;
	}

	hnode->childhead->next = (struct onas_lnode *) hnode->childtail;
	hnode->childtail->prev = (struct onas_lnode *) hnode->childhead;

	return hnode;
}

/* Function to initialize listnode. */
static struct onas_lnode *onas_listnode_init(void) {
	struct onas_lnode *lnode = NULL;
	if(!(lnode = (struct onas_lnode *) cli_malloc(sizeof(struct onas_lnode)))) {
		return NULL;
	}

	*lnode = (struct onas_lnode) {
		.dirname = NULL,
		.next = NULL,
		.prev = NULL
	};

	return lnode;
}

/* Function to free hashnode. */
void onas_free_hashnode(struct onas_hnode *hnode) {
	if (!hnode) return;

	onas_free_dirlist(hnode->childhead);
	hnode->childhead = NULL;

	free(hnode->pathname);
	hnode->pathname = NULL;

	free(hnode->prnt_pathname);
	hnode->prnt_pathname = NULL;

	free(hnode);

	return;
}


/* Function to free list of listnodes. */
void onas_free_dirlist(struct onas_lnode *head) {
	if (!head) return;
	struct onas_lnode *curr = head;
	struct onas_lnode *tmp = curr;

	while(curr) {
		tmp = curr->next;
		onas_free_listnode(curr);
		curr = tmp;
	}

	return;
}

/* Function to free a listnode. */
void onas_free_listnode(struct onas_lnode *lnode) {
	if (!lnode) return;

	lnode->next = NULL;
	lnode->prev = NULL;

	free(lnode->dirname);
	lnode->dirname = NULL;

	free(lnode);

	return;
}

static int onas_add_hashnode_child(struct onas_hnode *node, const char* dirname) {
	if (!node || !dirname) return CL_ENULLARG;

	struct onas_lnode *child = onas_listnode_init();
	if (!child) return CL_EMEM;
	
	size_t n = strlen(dirname);
	child->dirname = cli_strndup(dirname, n);

	onas_add_listnode(node->childtail, child);

	return CL_SUCCESS;
}

/* Function to add a dir_listnode to a list */
int onas_add_listnode(struct onas_lnode *tail, struct onas_lnode *node) {
	if (!tail || !node) return CL_ENULLARG;

	struct onas_lnode *tmp = tail->prev;

	tmp->next = node;
	node->prev = tail->prev;

	node->next = tail;
	tail->prev = node;

	return CL_SUCCESS;
}

/* Function to remove a listnode based on dirname. */
int onas_rm_listnode(struct onas_lnode *head, const char *dirname) {
	if (!dirname || !head) return CL_ENULLARG;

	struct onas_lnode *curr = head;
	size_t n = strlen(dirname);

	while ((curr = curr->next)) {
		if (!strncmp(curr->dirname, dirname, n)) {
			struct onas_lnode *tmp = curr->prev;
			tmp->next = curr->next;
			tmp = curr->next;
			tmp->prev = curr->prev;

			onas_free_listnode(curr);

			return CL_SUCCESS;
		}
	}

	return -1;
}

/*** Dealing with parent/child relationships in the table. ***/

/* Determines parent and returns a copy based on full pathname. */
inline static char *onas_get_parent(const char *pathname, size_t len) {
	if (!pathname || len <= 1) return NULL;

	int idx = len - 2;
	char *ret = NULL;

	while(idx >= 0 && pathname[idx] != '/') {
		idx--;
	}

	if (idx == 0) {
		idx++;
	}

	ret = cli_strndup(pathname, idx);
	if (!ret) {
		errno = ENOMEM;
		return NULL;
	}

	return ret;
}

/* Gets the index at which the name of directory begins from the full pathname. */
inline static int onas_get_dirname_idx(const char *pathname, size_t len) {
	if (!pathname || len <= 1) return -1;

	int idx = len - 2;

	while(idx >= 0 && pathname[idx] != '/') {
		idx--;
	}

	if (pathname[idx] == '/')
		return idx + 1;

	return idx;
}

/* Emancipates the specified child from the specified parent. */
int onas_ht_rm_child(struct onas_ht *ht, const char *prntpath, size_t prntlen, const char *childpath, size_t childlen) {

	if (!ht || !prntpath || prntlen <= 0 || !childpath || childlen <= 1) return CL_ENULLARG;

	struct onas_element *elem = NULL;
	struct onas_hnode *hnode = NULL;
	int idx = onas_get_dirname_idx(childpath, childlen);
	int ret = 0;

	if(idx <= 0) return CL_SUCCESS;

	if(onas_ht_get(ht, prntpath, prntlen, &elem) != CL_SUCCESS) return CL_EARG;

	hnode = elem->data;

	if ((ret = onas_rm_listnode(hnode->childhead, &(childpath[idx])))) return CL_EARG;

	return CL_SUCCESS;
}

/* The specified parent adds the specified child to its list. */
int onas_ht_add_child(struct onas_ht *ht, const char *prntpath, size_t prntlen, const char *childpath, size_t childlen) {
	if (!ht || !prntpath || prntlen <= 0 || !childpath || childlen <= 1) return CL_ENULLARG;

	struct onas_element *elem = NULL;
	struct onas_hnode *hnode = NULL;
	int idx = onas_get_dirname_idx(childpath, childlen);

	if(idx <= 0) return CL_SUCCESS;

	if(onas_ht_get(ht, prntpath, prntlen, &elem)) return CL_EARG;
	hnode = elem->data;

	return onas_add_hashnode_child(hnode, &(childpath[idx]));
}

/*** Dealing with hierarchy changes. ***/

/* Adds the hierarchy under pathname to the tree and allocates all necessary memory. */
int onas_ht_add_hierarchy(struct onas_ht *ht, const char *pathname) {

	if (!ht || !pathname) return CL_ENULLARG;

	FTS *ftsp = NULL;
	int ftspopts = FTS_PHYSICAL | FTS_XDEV;
	FTSENT *curr = NULL;
	FTSENT *childlist = NULL;

	size_t len = strlen(pathname);
	char *prnt = onas_get_parent(pathname, len);
	if (prnt) onas_ht_add_child(ht, prnt, strlen(prnt), pathname, len);
	free(prnt);

	char * const pathargv[] = { (char*) pathname, NULL };
	if (!(ftsp = _priv_fts_open(pathargv, ftspopts, NULL))) {
		logg("!ScanOnAccess: Could not open '%s'\n", pathname);
		return CL_EARG;
	}

	while((curr = _priv_fts_read(ftsp))) {

		struct onas_hnode *hnode = NULL;

		/* May want to handle other options in the future. */
		switch (curr->fts_info) {
			case FTS_D:
				hnode = onas_hashnode_init();
				if (!hnode) return CL_EMEM;

				hnode->pathlen = curr->fts_pathlen;
				hnode->pathname = cli_strndup(curr->fts_path, hnode->pathlen);

				hnode->prnt_pathname = onas_get_parent(hnode->pathname, hnode->pathlen);
				if (hnode->prnt_pathname)
					hnode->prnt_pathlen = strlen(hnode->prnt_pathname);
				else
					hnode->prnt_pathlen = 0;
				break;
			default:
				continue;
		}

		if((childlist = _priv_fts_children(ftsp, 0))) {
			do {
				if (childlist->fts_info == FTS_D) {
					if(CL_EMEM == onas_add_hashnode_child(hnode, childlist->fts_name))
						return CL_EMEM;
				}

			} while ((childlist = childlist->fts_link));
		}

		struct onas_element *elem = onas_element_init(hnode, hnode->pathname, hnode->pathlen);
		if (!elem) return CL_EMEM;

		if (onas_ht_insert(ht, elem)) return -1;
	}

	_priv_fts_close(ftsp);
	return CL_SUCCESS;
}

/* Removes the underlying hierarchy from the tree and frees all associated memory. */
int onas_ht_rm_hierarchy(struct onas_ht *ht, const char* pathname, size_t len, int level) {
	if (!ht || !pathname || len <= 0) return CL_ENULLARG;

	struct onas_hnode *hnode = NULL;
	struct onas_element *elem = NULL;
	char *prntname = NULL;
	size_t prntlen = 0;

	if(onas_ht_get(ht, pathname, len, &elem)) return CL_EARG;

	hnode = elem->data;

	struct onas_lnode *curr = hnode->childhead;

	if(level == 0) {
		if(!(prntname = onas_get_parent(pathname, len))) return CL_EARG;

		prntlen = strlen(prntname);
		if(onas_ht_rm_child(ht, prntname, prntlen, pathname, len)) return CL_EARG;

		free(prntname);
	}

	while (curr->next != hnode->childtail) {
		curr = curr->next;

		size_t size = len + strlen(curr->dirname) + 2;
		char *child_path = (char *) cli_malloc(size);
		if (child_path == NULL)
			return CL_EMEM;
		if (hnode->pathname[len-1] == '/')
			snprintf(child_path, size, "%s%s", hnode->pathname, curr->dirname);
		else
			snprintf(child_path, size, "%s/%s", hnode->pathname, curr->dirname);
		onas_ht_rm_hierarchy(ht, child_path, size, level + 1);
		free(child_path);
	}

	onas_ht_remove(ht, pathname, len, NULL);
	onas_free_element(elem);

	return CL_SUCCESS;
}
#endif
