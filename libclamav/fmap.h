/*
 *  Copyright (C) 2009 Sourcefire, Inc.
 *
 *  Authors: aCaB <acab@clamav.net>
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

#ifndef __FMAP_H
#define __FMAP_H

#include "cltypes.h"

//#define FMAPDEBUG

struct F_MAP {
    int fd;
    unsigned int dumb;
    time_t mtime;
    size_t offset;
    size_t len;
    unsigned int pages;
    unsigned int hdrsz;
    unsigned int pgsz;
    unsigned int paged;
#ifdef FMAPDEBUG
  unsigned int page_needs;
  unsigned int page_reads;
  unsigned int page_locks;
  unsigned int page_unlocks;
  unsigned int page_unmaps;
#endif
    uint32_t bitmap[]; /* FIXME: do not use flexible arrays */
};

struct F_MAP *fmap(int fd, off_t offset, size_t len);
void fmunmap(struct F_MAP *m);
void *fmap_need_off(struct F_MAP *m, size_t at, size_t len);
void *fmap_need_off_once(struct F_MAP *m, size_t at, size_t len);
void *fmap_need_ptr(struct F_MAP *m, void *ptr, size_t len);
void *fmap_need_ptr_once(struct F_MAP *m, void *ptr, size_t len);
void fmap_unneed_off(struct F_MAP *m, size_t at, size_t len);
void fmap_unneed_ptr(struct F_MAP *m, void *ptr, size_t len);
int fmap_readn(struct F_MAP *m, void *dst, size_t at, size_t len);
void *fmap_need_str(struct F_MAP *m, void *ptr, size_t len_hint);
void *fmap_need_offstr(struct F_MAP *m, size_t at, size_t len_hint);
void *fmap_gets(struct F_MAP *m, char *dst, size_t *at, size_t max_len);
#endif
