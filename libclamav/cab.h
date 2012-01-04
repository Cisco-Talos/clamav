/*
 *  Copyright (C) 2007-2008 Sourcefire, Inc.
 *
 *  Authors: Tomasz Kojm
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

#ifndef __CAB_H
#define __CAB_H

#include <sys/types.h>
#include "cltypes.h"
#include "fmap.h"

#define CAB_BLOCKMAX 65535
#define CAB_INPUTMAX (CAB_BLOCKMAX + 6144)

struct cab_archive {
    struct cab_folder *folders, *actfol;
    struct cab_file *files;
    struct cab_state *state;
    fmap_t *map;
    off_t cur_offset;
    uint32_t length;
    uint16_t nfolders;
    uint16_t nfiles;
    uint16_t flags;
    uint16_t reshdr;
    uint8_t resdata;
};

struct cab_state {
    unsigned char *pt, *end;
    void *stream;
    unsigned char block[CAB_INPUTMAX];
    uint16_t blklen;
    uint16_t outlen;
    uint16_t blknum;
    uint16_t cmethod;
};

struct cab_file {
    off_t offset;
    char *name;
    uint32_t length;
    int error;
    int lread;
    int ofd;
    struct cab_folder *folder;
    struct cab_file *next;
    struct cab_archive *cab;
    uint16_t attribs;
    uint64_t max_size, written_size;
};

struct cab_folder {
    struct cab_archive *cab;
    off_t offset;
    struct cab_folder *next;
    uint16_t cmethod;
    uint16_t nblocks;
};

int cab_open(fmap_t *map, off_t offset, struct cab_archive *cab);
int cab_extract(struct cab_file *file, const char *name);
void cab_free(struct cab_archive *cab);

#endif
