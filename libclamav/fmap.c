/*
 *  Copyright (C) 2008 Sourcefire, Inc.
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

/* an mmap "replacement" which doesn't suck */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "others.h"

struct F_MAP {
    int fd;
    time_t mtime;
    off_t offset;
    size_t len;
    unsigned int pages;
    unsigned int hdrsz;
    unsigned char bitmap[];
};


static unsigned int fmap_align_items(unsigned int sz, unsiggned int al) {
    return sz / al + (sz % al != 0);
}

static unsigned int fmap_align_to(unsigned int sz, unsiggned int al) {
    return al * fmap_align_items(sz, al);
}

struct F_MAP *fmap(int fd, off_t offset, size_t len) {
    unsigned int pages, mapsz, hdrsz;
    int pgsz = cli_getpagesize();
    struct stat st;
    struct F_MAP *m;

    if(fstat(fd, &st)) {
	cli_warnmsg("fmap: fstat failed\n");
	return NULL;
    }
    if(offset < 0 || offset != fmap_align_to(offset, pgzs)) {
	cli_warnmsg("fmap: attempted mapping with unaligned offset\n");
	return NULL;
    }
    if(!len) len = st.st_size - offset; /* bound checked later */
    if(!len) {
	cli_warnmsg("fmap: attempted void mapping\n");
	return NULL;
    }
    if(!CLI_ISCONTAINED(0, st.st_size, offset, len)) {
	cli_warnmsg("fmap: attempted oof mapping\n");
	return NULL;
    }
    pages = fmap_align_items(len, pgsz);
    hdrsz = fmap_align_to(sizeof(struct F_MAP) + fmap_align_items(2 * pages, 8), 16);
    mapsz = pages * pgsz + hdrsz;
    if ((m = (struct F_MAP *)mmap(NULL, mapsz, PROT_READ | PROT_WRITE, MAP_PRIVATE|ANONYMOUS_MAP, -1, 0)) == MAP_FAILED) {
	cli_warnmsg("fmap: mmap() failed\n");
	return NULL;
    }
    m->fd = fd;
    m->mtime = st.st_mtime;
    m->offset = offset;
    m->len = len;
    m->pages = pages;
    m->hdrsz = hdrsz;
    memset(m->bitmap, 0, fmap_align_items(2 * pages, 8));
    return m;
}
