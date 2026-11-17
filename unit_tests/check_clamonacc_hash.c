/*
 * Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2.
 */

#include "clamav-config.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "clamav.h"
#include "../clamonacc/inotif/hash.h"

/* No fanotify permissions or running clamd are needed: test the directory
 * links which onas_ddd_watch_hierarchy follows to install its watches. */
static int check_tree(struct onas_ht *ht, const char *path, unsigned int *remaining)
{
    struct onas_element *elem = NULL;
    struct onas_lnode *child  = NULL;
    struct onas_hnode *node   = NULL;
    char child_path[512];
    int len;

    if (*remaining == 0 || onas_ht_get(ht, path, strlen(path), &elem) != CL_SUCCESS) {
        fprintf(stderr, "Unexpected or missing directory: %s\n", path);
        return 1;
    }
    --*remaining;
    node = elem->data;
    for (child = node->childhead->next; child != node->childtail; child = child->next) {
        len = snprintf(child_path, sizeof(child_path), "%s%s%s", path,
                       path[strlen(path) - 1] == '/' ? "" : "/", child->dirname);
        if (len < 0 || (size_t)len >= sizeof(child_path) || check_tree(ht, child_path, remaining)) {
            return 1;
        }
    }
    return 0;
}

static int check_hierarchy(const char *root, const char *added)
{
    struct onas_ht *ht = NULL;
    unsigned int remaining;
    int ret = 1;

    if (onas_ht_init(&ht, 1024) != CL_SUCCESS || onas_ht_add_hierarchy(ht, root) != CL_SUCCESS) {
        goto out;
    }

    /* Existing nested directories and siblings must all be reachable. Files
     * and symlinks to directories must not become directory children. */
    remaining = 4;
    if (check_tree(ht, root, &remaining) || remaining != 0) {
        fprintf(stderr, "Existing directory hierarchy is incomplete\n");
        goto out;
    }

    /* Also exercise the root-to-existing-parent link used for new directories. */
    if (mkdir(added, 0700) != 0 || onas_ht_add_hierarchy(ht, added) != CL_SUCCESS) {
        goto out;
    }
    remaining = 5;
    if (check_tree(ht, root, &remaining) || remaining != 0) {
        fprintf(stderr, "Incremental directory hierarchy is incomplete\n");
        goto out;
    }
    ret = 0;

out:
    rmdir(added);
    onas_free_ht(ht);
    return ret;
}

int main(void)
{
    char root[] = "/tmp/clamav-ddd-XXXXXX";
    char nested[512], leaf[512], sibling[512], regular[512], link[512], added[512], trailing[512];
    FILE *file = NULL;
    int ret    = 1;

    if (mkdtemp(root) == NULL) {
        perror("mkdtemp");
        return 1;
    }
    snprintf(nested, sizeof(nested), "%s/nested", root);
    snprintf(leaf, sizeof(leaf), "%s/nested/leaf", root);
    snprintf(sibling, sizeof(sibling), "%s/sibling", root);
    snprintf(regular, sizeof(regular), "%s/file", root);
    snprintf(link, sizeof(link), "%s/link", root);
    snprintf(added, sizeof(added), "%s/nested/added", root);
    snprintf(trailing, sizeof(trailing), "%s/", root);

    if (mkdir(nested, 0700) != 0 || mkdir(leaf, 0700) != 0 || mkdir(sibling, 0700) != 0) {
        goto out;
    }
    file = fopen(regular, "w");
    if (file == NULL) {
        goto out;
    }
    fclose(file);
    if (symlink(nested, link) != 0) {
        goto out;
    }

    if (check_hierarchy(root, added) || check_hierarchy(trailing, added)) {
        goto out;
    }
    ret = 0;

out:
    unlink(link);
    unlink(regular);
    rmdir(sibling);
    rmdir(leaf);
    rmdir(nested);
    rmdir(root);
    return ret;
}
