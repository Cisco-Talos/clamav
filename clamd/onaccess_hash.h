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

#ifndef __ONAS_HASH_H
#define __ONAS_HASH_H

#define ONAS_FANWATCH   0x1
#define ONAS_INWATCH   0x2
#define ONAS_STOPWATCH 0x3

#define ONAS_DEFAULT_HT_SIZE 1 << 18

struct onas_element {

	const char* key;
	size_t klen;
	struct onas_hnode *data;

	struct onas_element *next;
	struct onas_element *prev;
};

struct onas_bucket {

	uint32_t size;

	struct onas_element *head;
	struct onas_element *tail;
};

struct onas_ht {

	struct onas_bucket **htable;

	/* Must be a sufficiently high power of two--will not grow. */
	uint32_t size;
	uint32_t nbckts;
};

/* Directory node struct for lists */
struct onas_lnode {

	/* List stuffs */
	char *dirname;
	struct onas_lnode *next;
	struct onas_lnode *prev;
};

/* Directory node struct for hash tables */
struct onas_hnode {

	/* Path info */
	int pathlen;
	char *pathname;

	/* Parent info */
	int prnt_pathlen;
	char *prnt_pathname;

	/* Child head and tail are empty sentinels */
	struct onas_lnode *childhead;
	struct onas_lnode *childtail;

	/* Inotify watch descriptor */
	int wd;

	/* Watched stuffs */
	uint32_t watched;
};


void onas_free_ht(struct onas_ht *ht);
int onas_ht_init(struct onas_ht **ht, uint32_t table_size);
int onas_ht_insert(struct onas_ht *ht, struct onas_element *elem);
int onas_ht_remove(struct onas_ht *ht, const char *key, size_t klen, struct onas_element **elem);
int onas_ht_get(struct onas_ht *ht, const char *key, size_t klen, struct onas_element **elem);
int onas_ht_rm_hierarchy(struct onas_ht *ht, const char *pathname, size_t len, int level);
int onas_ht_add_hierarchy(struct onas_ht *ht, const char *pathname);
int onas_ht_add_child(struct onas_ht *ht, const char *prntpath, size_t prntlen, const char *childpath, size_t childlen);
int onas_ht_rm_child(struct onas_ht *ht, const char *prntpath, size_t prntlen, const char *childpath, size_t childlen);

void onas_free_element(struct onas_element *elem);
struct onas_element *onas_element_init(struct onas_hnode *value, const char *key, size_t klen);

void onas_free_hashnode(struct onas_hnode *hnode);

void onas_free_listnode(struct onas_lnode *lnode);
int onas_add_listnode(struct onas_lnode *tail, struct onas_lnode *node);
int onas_rm_listnode(struct onas_lnode *head, const char *dirname);

void onas_free_dirlist(struct onas_lnode *head);

#endif
