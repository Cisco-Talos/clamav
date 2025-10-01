/*
 *  Copyright (C) 2015-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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

#if defined(HAVE_SYS_FANOTIFY_H)
#include <sys/fanotify.h>
#endif

// libclamav
#include "clamav.h"
#include "scanners.h"
#include "str.h"

// common
#include "optparser.h"
#include "output.h"

// clamd
#include "server.h"
#include "clamd_others.h"
#include "scanner.h"

#include "../fanotif/fanotif.h"
#include "hash.h"
#include "inotif.h"
#include "../misc/priv_fts.h"

#if defined(HAVE_SYS_FANOTIFY_H)

static struct onas_bucket *onas_bucket_init(void);
static void onas_free_bucket(struct onas_bucket *bckt);
static int onas_bucket_insert(struct onas_bucket *bckt, struct onas_element *elem);
static int onas_bucket_remove(struct onas_bucket *bckt, struct onas_element *elem);

static int onas_add_hashnode_child(struct onas_hnode *node, const char *dirname);

static struct onas_lnode *onas_listnode_init(void);

static struct onas_hnode *onas_hashnode_init(void);

/**
 * The data structure described and implemented below is a hash table with elements that also act as relational nodes
 * in a tree. This allows for average case constant time retrieval of nodes, and recursive operation on a node and all
 * its children and parents. The memory cost for this speed of relational retrieval is necessarily high, as every node
 * must also keep track of its children in a key-accessible way. To cut down on memory costs, children of nodes are not
 * themselves key accessible, but must be combined with their parent in a constant-time operation to be retrieved from
 * the table.
 *
 * Further optimization to retrieval and space management may include storing direct address to given children nodes, but
 * such a design will create further complexity and time cost at insertion--which must also be as fast as possible in
 * order to accommodate the real-time nature of security event processing.
 *
 * To date, the hashing function itself has not been well studied, and as such buckets were implemented from the start to
 * help account for any potential collision issues in its design, as a measure to help offset any major time sinks during
 * insertion.
 *
 * One last important note about this hash table is that to avoid massive slowdowns, it does not grow, but instead relies on
 * buckets and a generous default size to distribute that load. Slight hit to retrieval time is a fair cost to pay to avoid
 * total loss of service in a real-time system. Future work here might include automatically configuring initial hashtable
 * size to align with the system being monitored, or max inotify watch points since that's our hard limit anyways.
 */

static inline uint32_t onas_hshift(uint32_t hash)
{

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

/**
 * @brief inline wrapper for onaccess inotify hashing function
 *
 * @param key       the string to be hashed
 * @param keylen    size of the string
 * @param size      the size of the hashtable
 */
static inline int onas_hash(const char *key, size_t keylen, uint32_t size)
{

    uint32_t hash = 1;
    uint32_t i;

    for (i = 0; i < keylen; i++) {
        hash += key[i];
        hash = onas_hshift(hash);
    }

    return hash & (size - 1);
}

/**
 * @brief initialises a bucketed hash table, pre-grown to the given size
 */
int onas_ht_init(struct onas_ht **ht, uint32_t size)
{

    if (size == 0 || (size & (~size + 1)) != size) return CL_EARG;

    *ht = (struct onas_ht *)malloc(sizeof(struct onas_ht));
    if (!(*ht)) return CL_EMEM;

    **ht = (struct onas_ht){
        .htable = NULL,
        .size   = size,
        .head   = NULL,
        .tail   = NULL,
        .nbckts = 0,
    };

    if (!((*ht)->htable = (struct onas_bucket **)calloc(size, sizeof(struct onas_bucket *)))) {
        onas_free_ht(*ht);
        return CL_EMEM;
    }

    return CL_SUCCESS;
}

void onas_free_ht(struct onas_ht *ht)
{

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

static struct onas_bucket *onas_bucket_init()
{

    struct onas_bucket *bckt = (struct onas_bucket *)malloc(sizeof(struct onas_bucket));
    if (!bckt) return NULL;

    *bckt = (struct onas_bucket){
        .size = 0,
        .head = NULL,
        .tail = NULL};

    return bckt;
}

static void onas_free_bucket(struct onas_bucket *bckt)
{

    if (!bckt) return;

    uint32_t i                = 0;
    struct onas_element *curr = NULL;

    for (i = 0; i < bckt->size; i++) {
        curr       = bckt->head;
        bckt->head = curr->next;
        onas_free_element(curr);
        curr = NULL;
    }

    free(bckt);

    return;
}
/**
 * @brief the hash table uses buckets to store lists of key/value pairings
 */
struct onas_element *onas_element_init(struct onas_hnode *value, const char *key, size_t klen)
{

    struct onas_element *elem = (struct onas_element *)malloc(sizeof(struct onas_element));
    if (!elem) return NULL;

    *elem = (struct onas_element){
        .key  = key,
        .klen = klen,
        .data = value,
        .next = NULL,
        .prev = NULL};

    return elem;
}

void onas_free_element(struct onas_element *elem)
{

    if (!elem) return;

    onas_free_hashnode(elem->data);

    elem->prev = NULL;
    elem->next = NULL;

    free(elem);

    return;
}

int onas_ht_insert(struct onas_ht *ht, struct onas_element *elem)
{

    if (!ht || !elem || !elem->key) return CL_ENULLARG;

    int idx                  = onas_hash(elem->key, elem->klen, ht->size);
    struct onas_bucket *bckt = ht->htable[idx];

    int ret        = 0;
    uint32_t bsize = 0;

    if (bckt == NULL) {
        ht->htable[idx] = onas_bucket_init();
        if (ht->htable[idx] == NULL) return CL_EMEM;

        bckt = ht->htable[idx];
    }

    /* Init activated buckets */
    if (ht->nbckts == 0) {
        ht->head   = bckt;
        ht->tail   = bckt;
        bckt->prev = NULL;
        bckt->next = NULL;
    } else {
        struct onas_bucket *ht_tail = ht->tail;
        ht_tail->next               = bckt;
        bckt->prev                  = ht_tail;
        bckt->next                  = NULL;
        ht->tail                    = bckt;
    }
    bsize = bckt->size;
    ret   = onas_bucket_insert(bckt, elem);

    if (ret == CL_SUCCESS)
        if (bsize < bckt->size)
            ht->nbckts++;

    return ret;
}

static int onas_bucket_insert(struct onas_bucket *bckt, struct onas_element *elem)
{
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
        elem->prev  = btail;
        elem->next  = NULL;
        bckt->tail  = elem;
        bckt->size++;
    }

    return CL_SUCCESS;
}

/**
 * @brief Checks if key exists and optionally stores address to the element corresponding to the key within elem
 */
int onas_ht_get(struct onas_ht *ht, const char *key, size_t klen, struct onas_element **elem)
{

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

/**
 * @brief Removes the element corresponding to key from the hashtable and optionally returns a pointer to the removed element.
 */
int onas_ht_remove(struct onas_ht *ht, const char *key, size_t klen, struct onas_element **relem)
{
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

static int onas_bucket_remove(struct onas_bucket *bckt, struct onas_element *elem)
{
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
            tmp       = elem->next;
            tmp->prev = elem->prev;
        }

        elem->prev = NULL;
        elem->next = NULL;
    }

    bckt->size--;

    return CL_SUCCESS;
}

/* Dealing with hash nodes and list nodes */

/**
 * @brief Function to initialize hashnode, which is the data value we're storing in the hash table
 */
static struct onas_hnode *onas_hashnode_init(void)
{
    struct onas_hnode *hnode = NULL;
    if (!(hnode = (struct onas_hnode *)malloc(sizeof(struct onas_hnode)))) {
        return NULL;
    }

    *hnode = (struct onas_hnode){
        .pathlen       = 0,
        .pathname      = NULL,
        .prnt_pathlen  = 0,
        .prnt_pathname = NULL,
        .childhead     = NULL,
        .childtail     = NULL,
        .wd            = 0,
        .watched       = 0};

    if (!(hnode->childhead = (struct onas_lnode *)onas_listnode_init())) {
        onas_free_hashnode(hnode);
        return NULL;
    }

    if (!(hnode->childtail = (struct onas_lnode *)onas_listnode_init())) {
        onas_free_hashnode(hnode);
        return NULL;
    }

    hnode->childhead->next = (struct onas_lnode *)hnode->childtail;
    hnode->childtail->prev = (struct onas_lnode *)hnode->childhead;

    return hnode;
}

/**
 * @brief Function to initialize listnodes, which ultimately allow us to traverse this datastructure like a tree
 */
static struct onas_lnode *onas_listnode_init(void)
{
    struct onas_lnode *lnode = NULL;
    if (!(lnode = (struct onas_lnode *)malloc(sizeof(struct onas_lnode)))) {
        return NULL;
    }

    *lnode = (struct onas_lnode){
        .dirname = NULL,
        .next    = NULL,
        .prev    = NULL};

    return lnode;
}

/**
 * @brief Function to free hashnodes
 */
void onas_free_hashnode(struct onas_hnode *hnode)
{
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

/**
 * @brief Function to free list of listnode
 */
void onas_free_dirlist(struct onas_lnode *head)
{
    if (!head) return;
    struct onas_lnode *curr = head;
    struct onas_lnode *tmp  = curr;

    while (curr) {
        tmp = curr->next;
        onas_free_listnode(curr);
        curr = tmp;
    }

    return;
}

/**
 * @brief Function to free a single listnode
 */
void onas_free_listnode(struct onas_lnode *lnode)
{
    if (!lnode) return;

    lnode->next = NULL;
    lnode->prev = NULL;

    free(lnode->dirname);
    lnode->dirname = NULL;

    free(lnode);

    return;
}

/**
 * @brief Function to add a single value to a hashnode's listnode
 */
static int onas_add_hashnode_child(struct onas_hnode *node, const char *dirname)
{
    if (!node || !dirname) return CL_ENULLARG;

    struct onas_lnode *child = onas_listnode_init();
    if (!child) return CL_EMEM;

    size_t n       = strlen(dirname);
    child->dirname = CLI_STRNDUP(dirname, n);

    onas_add_listnode(node->childtail, child);

    return CL_SUCCESS;
}

/**
 * @brief Function to add a dir_listnode to a list
 */
int onas_add_listnode(struct onas_lnode *tail, struct onas_lnode *node)
{
    if (!tail || !node) return CL_ENULLARG;

    struct onas_lnode *tmp = tail->prev;

    tmp->next  = node;
    node->prev = tail->prev;

    node->next = tail;
    tail->prev = node;

    return CL_SUCCESS;
}

/**
 * @brief Function to remove a listnode based on dirname.
 */
cl_error_t onas_rm_listnode(struct onas_lnode *head, const char *dirname)
{
    if (!dirname || !head) return CL_ENULLARG;

    struct onas_lnode *curr = head;
    size_t n                = strlen(dirname);

    while ((curr = curr->next)) {
        if (NULL == curr->dirname) {
            logg(LOGG_DEBUG, "ClamHash: node's directory name is NULL!\n");
            return CL_ERROR;
        } else if (!strncmp(curr->dirname, dirname, n)) {
            if (curr->next != NULL)
                curr->next->prev = curr->prev;
            if (curr->prev != NULL)
                curr->prev->next = curr->next;
            onas_free_listnode(curr);

            return CL_SUCCESS;
        }
    }

    return CL_ERROR;
}

/*** Dealing with parent/child relationships in the table. ***/

/**
 * @brief Determines parent of given directory and returns a copy based on full pathname.
 */
inline static char *onas_get_parent(const char *pathname, size_t len)
{
    if (!pathname || len <= 1) return NULL;

    int idx   = len - 2;
    char *ret = NULL;

    while (idx >= 0 && pathname[idx] != '/') {
        idx--;
    }

    if (idx == 0) {
        idx++;
    }

    ret = CLI_STRNDUP(pathname, idx);
    if (!ret) {
        errno = ENOMEM;
        return NULL;
    }

    return ret;
}

/**
 * @brief Gets the index at which the name of directory begins from the full pathname.
 */
inline static int onas_get_dirname_idx(const char *pathname, size_t len)
{
    if (!pathname || len <= 1) return -1;

    int idx = len - 2;

    while (idx >= 0 && pathname[idx] != '/') {
        idx--;
    }

    if (pathname[idx] == '/')
        return idx + 1;

    return idx;
}

/**
 * @brief Emancipates the specified child from the specified parent directory, typical done after a delete or move event
 *
 * @param ht        the hashtable structure
 * @param prntpath  the full path of the parent director to be used hashed and used as a key to retrieve the corresponding entry from the table
 * @param prntlen   the length of the parent path in bytes
 * @param childpath the path of the child to be deassociated with the passed parent
 * @param childlen  the length of the child path in bytes
 */
int onas_ht_rm_child(struct onas_ht *ht, const char *prntpath, size_t prntlen, const char *childpath, size_t childlen)
{

    if (!ht || !prntpath || prntlen <= 0 || !childpath || childlen <= 1) return CL_ENULLARG;

    struct onas_element *elem = NULL;
    struct onas_hnode *hnode  = NULL;
    int idx                   = onas_get_dirname_idx(childpath, childlen);
    int ret                   = 0;

    if (idx <= 0) return CL_SUCCESS;

    if (onas_ht_get(ht, prntpath, prntlen, &elem) != CL_SUCCESS) return CL_EARG;

    hnode = elem->data;

    if (CL_SUCCESS != (ret = onas_rm_listnode(hnode->childhead, &(childpath[idx])))) {
        return CL_EARG;
    }

    return CL_SUCCESS;
}

/**
 * @brief The specified parent adds the specified child to its list, typical done after a create, or move event
 *
 * @param ht        the hashtable structure
 * @param prntpath  the full path of the parent director to be used hashed and used as a key to retrieve the corresponding entry from the table
 * @param prntlen   the length of the parent path in bytes
 * @param childpath the path of the child to be associated with the passed parent
 * @param childlen  the length of the child path in bytes
 */
int onas_ht_add_child(struct onas_ht *ht, const char *prntpath, size_t prntlen, const char *childpath, size_t childlen)
{
    if (!ht || !prntpath || prntlen <= 0 || !childpath || childlen <= 1) return CL_ENULLARG;

    struct onas_element *elem = NULL;
    struct onas_hnode *hnode  = NULL;
    int idx                   = onas_get_dirname_idx(childpath, childlen);

    if (idx <= 0) return CL_SUCCESS;

    if (onas_ht_get(ht, prntpath, prntlen, &elem)) return CL_EARG;
    hnode = elem->data;

    return onas_add_hashnode_child(hnode, &(childpath[idx]));
}

/*** Dealing with hierarchy changes. ***/

/**
 * @brief Adds the hierarchy under pathname to the tree and allocates all necessary memory.
 */
int onas_ht_add_hierarchy(struct onas_ht *ht, const char *pathname)
{
    if (!ht || !pathname) return CL_ENULLARG;

    int ret           = 0;
    FTS *ftsp         = NULL;
    int ftspopts      = FTS_PHYSICAL | FTS_XDEV;
    FTSENT *curr      = NULL;
    FTSENT *childlist = NULL;

    size_t len = strlen(pathname);
    char *prnt = onas_get_parent(pathname, len);
    if (prnt) onas_ht_add_child(ht, prnt, strlen(prnt), pathname, len);
    free(prnt);

    char *const pathargv[] = {(char *)pathname, NULL};
    if (!(ftsp = _priv_fts_open(pathargv, ftspopts, NULL))) {
        logg(LOGG_ERROR, "ClamHash: could not open '%s'\n", pathname);
        ret = CL_EARG;
        goto out;
    }

    while ((curr = _priv_fts_read(ftsp))) {

        struct onas_hnode *hnode = NULL;

        /* May want to handle other options in the future. */
        switch (curr->fts_info) {
            case FTS_D:
                hnode = onas_hashnode_init();
                if (!hnode) {
                    ret = CL_EMEM;
                    goto out;
                }

                hnode->pathlen  = curr->fts_pathlen;
                hnode->pathname = CLI_STRNDUP(curr->fts_path, hnode->pathlen);

                hnode->prnt_pathname = onas_get_parent(hnode->pathname, hnode->pathlen);
                if (hnode->prnt_pathname)
                    hnode->prnt_pathlen = strlen(hnode->prnt_pathname);
                else
                    hnode->prnt_pathlen = 0;
                break;
            default:
                continue;
        }

        if ((childlist = _priv_fts_children(ftsp, 0))) {
            do {
                if (childlist->fts_info == FTS_D) {
                    if (CL_EMEM == onas_add_hashnode_child(hnode, childlist->fts_name)) {

                        ret = CL_EMEM;
                        onas_free_hashnode(hnode);
                        goto out;
                    }
                }
            } while ((childlist = childlist->fts_link));
        }

        struct onas_element *elem = onas_element_init(hnode, hnode->pathname, hnode->pathlen);
        if (!elem) {
            ret = CL_EMEM;
            onas_free_hashnode(hnode);
            goto out;
        }

        if (onas_ht_insert(ht, elem)) {
            ret = -1;
            /* Note: `onas_free_hashnode(hnode) will get called by the
             *       `onas_free_element` call below */
            onas_free_element(elem);
            goto out;
        }
    }

out:
    if (ftsp) {
        _priv_fts_close(ftsp);
    }

    if (ret) {
        return ret;
    }

    return CL_SUCCESS;
}

/**
 * @brief Removes the underlying hierarchy from the tree and frees all associated memory.
 */
int onas_ht_rm_hierarchy(struct onas_ht *ht, const char *pathname, size_t len, int level)
{
    if (!ht || !pathname || len <= 0) return CL_ENULLARG;

    struct onas_hnode *hnode  = NULL;
    struct onas_element *elem = NULL;
    char *prntname            = NULL;
    size_t prntlen            = 0;

    if (onas_ht_get(ht, pathname, len, &elem)) return CL_EARG;

    hnode = elem->data;

    struct onas_lnode *curr = hnode->childhead;

    if (level == 0) {
        if (!(prntname = onas_get_parent(pathname, len))) return CL_EARG;

        prntlen = strlen(prntname);
        if (onas_ht_rm_child(ht, prntname, prntlen, pathname, len)) {
            free(prntname);
            return CL_EARG;
        }

        free(prntname);
    }

    while (curr->next != hnode->childtail) {
        curr = curr->next;

        size_t size      = len + strlen(curr->dirname) + 2;
        char *child_path = (char *)malloc(size);
        if (child_path == NULL)
            return CL_EMEM;
        if (hnode->pathname[len - 1] == '/')
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
