/*
 *  Copyright (C) 2021-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2005-2010 Gianluigi Tiesi <sherpya@netfarm.it>
 *
 *  Authors: Gianluigi Tiesi
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

#ifndef __SCANMEM_H
#define __SCANMEM_H

#include <clamav-types.h>

#ifndef TH32CS_SNAPMODULE32
#define TH32CS_SNAPMODULE32 0x00000010
#endif

#define TIMEOUT_MODULE 30000

int scanmem(struct mem_info *info);

/* cache helpers */
typedef struct _filelist_t {
    char filename[MAX_PATH];
    int res;
    struct _filelist_t *next;
} filelist_t;

/* Callback */
typedef struct _cb_data_t {
    const char *filename;
    size_t size, count;
    int oldvalue;
    int fd;
} cb_data_t;

typedef struct _scanmem_data_t {
    filelist_t *files;
    int printclean, kill, unload, exclude;
    int res;
    uint32_t processes, modules;

} scanmem_data;

struct mem_info {
    unsigned int d;         /*1 = clamdscan, 0 = clamscan */
    unsigned int files;     /* number of scanned files */
    unsigned int ifiles;    /* number of infected files */
    uint64_t bytes_scanned; /* number of *scanned* bytes */
    unsigned int errors;

    struct cl_engine *engine;
    const struct optstruct *opts;
    struct cl_scan_options *options;
};

#endif
