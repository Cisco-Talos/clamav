/*
 *  Copyright (C) 2006 Tomasz Kojm <tkojm@clamav.net>
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

#define CAB_BLOCKMAX 32768
#define CAB_INPUTMAX (CAB_BLOCKMAX + 6144)

struct cab_archive {
    uint32_t length;
    uint16_t nfolders;
    uint16_t nfiles;
    uint16_t flags;
    uint16_t reshdr;
    uint8_t resdata;
    struct cab_folder *folders;
    struct cab_file *files;
};

struct cab_state {
    unsigned char *pt, *end;
    unsigned char block[CAB_INPUTMAX];
    uint16_t blklen;
    uint16_t outlen;
    void *stream;
    uint16_t blknum;
};

struct cab_file {
    uint32_t length;
    uint16_t attribs;
    off_t offset;
    char *name;
    int error;
    int fd;
    int ofd;
    struct cab_folder *folder;
    struct cab_file *next;
    struct cab_archive *cab;
    struct cab_state *state;
};

struct cab_folder {
    uint16_t cmethod;
    uint16_t nblocks;
    struct cab_archive *cab;
    off_t offset;
    struct cab_folder *next;
};

int cab_open(int fd, off_t offset, struct cab_archive *cab);
int cab_extract(struct cab_file *file, const char *name);
void cab_free(struct cab_archive *cab);

#endif
