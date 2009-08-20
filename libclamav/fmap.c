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

/* an mmap "replacement" which doesn't suck */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

/* THIS IS FUCKED UP AND BREAKS MMAP
#define _XOPEN_SOURCE 500
*/

#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

#include "others.h"
#include "cltypes.h"

#define FM_MASK_SCORE 0x3fff
#define FM_MASK_PAGED 0x4000
#define FM_MASK_SEEN 0x8000
#define FM_SCORE 8

struct F_MAP {
    int fd;
    time_t mtime;
    size_t offset;
    size_t len;
    unsigned int pages;
    unsigned int hdrsz;
    unsigned int pgsz;
    uint16_t bitmap[]; /* FIXME: do not use flexible arrays */
};


static unsigned int fmap_align_items(unsigned int sz, unsigned int al) {
    return sz / al + (sz % al != 0);
}

static unsigned int fmap_align_to(unsigned int sz, unsigned int al) {
    return al * fmap_align_items(sz, al);
}

static unsigned int fmap_which_page(struct F_MAP *m, size_t at) {
    return at / m->pgsz;
}

static unsigned int fmap_is_paged(struct F_MAP *m, unsigned int page) {
    uint16_t s = m->bitmap[page];
    return ((s & FM_MASK_PAGED) != 0);
}

static unsigned int fmap_is_seen(struct F_MAP *m, unsigned int page) {
    uint16_t s = m->bitmap[page];
    return ((s & FM_MASK_SEEN) != 0);
}

static void fmap_inc_page(struct F_MAP *m, unsigned int page) {
    uint16_t s = m->bitmap[page] & FM_MASK_SCORE;
    if(s < FM_MASK_SCORE - FM_SCORE)
	m->bitmap[page] += FM_SCORE;
    else
	m->bitmap[page] |= FM_MASK_SCORE;
}

static void fmap_dec_page(struct F_MAP *m, unsigned int page) {
    uint16_t s = m->bitmap[page] & FM_MASK_SCORE;
    if(s) m->bitmap[page]--;
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
    if(offset < 0 || offset != fmap_align_to(offset, pgsz)) {
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
    hdrsz = fmap_align_to(sizeof(struct F_MAP) + pages * sizeof(uint16_t), pgsz);
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
    m->pgsz = pgsz;
    memset(m->bitmap, 0, fmap_align_items(2 * pages, 8));
    return m;
}

static int fmap_readpage(struct F_MAP *m, unsigned int page) {
    size_t readsz;
    char *pptr;

    fmap_inc_page(m, page);
    if(fmap_is_paged(m, page))
	return 0;
    pptr = (char *)m;
    pptr += page * m->pgsz + m->hdrsz;
    if(page == m->pages - 1)
	readsz = m->len % m->pgsz;
    else
	readsz = m->pgsz;
    if(pread(m->fd, pptr, m->pgsz, m->offset + page * m->pgsz) != readsz)
	return 1;
    return 0;
}

void *fmap_need_off(struct F_MAP *m, size_t at, size_t len) {
    unsigned int i, first_page, last_page;
    char *ret;

    if(!len) {
	cli_warnmsg("fmap: attempted void need\n");
	return NULL;
    }

    if(!CLI_ISCONTAINED(0, m->len, at, len)) {
	cli_warnmsg("fmap: attempted oof need\n");
	return NULL;
    }
    
    first_page = fmap_which_page(m, at);
    last_page = fmap_which_page(m, at + len);    

    for(i=first_page; i<=last_page; i++) {
	if(fmap_readpage(m, i))
	    return NULL;
    }
    ret = (char *)m;
    ret += at + m->hdrsz;
    return (void *)ret;
}

void *fmap_need_ptr(struct F_MAP *m, void *ptr, size_t len) {
    return fmap_need_off(m, (char *)ptr - (char *)m - m->hdrsz, len);
}

void *fmap_need_str(struct F_MAP *m, void *ptr, size_t len) {
    const size_t at = (char *)ptr - (char *)m - m->hdrsz;
    unsigned int i, first_page, last_page;

    if(!len)
	len = m->len - at;

    if(!CLI_ISCONTAINED(0, m->len, at, len)) {
	cli_warnmsg("fmap: attempted oof need_str\n");
	return NULL;
    }

    first_page = fmap_which_page(m, at);
    last_page = fmap_which_page(m, at + len);    

    for(i=first_page; i<=last_page; i++) {
	char *thispage = (char *)m + m->hdrsz;
	unsigned int scanat, scansz;
	
	if(fmap_readpage(m, i))
	    return NULL;
	if(i == first_page) {
	    scanat = at % m->pgsz;
	    scansz = m->pgsz - scanat;
	} else {
	    scanat = 0;
	    scansz = m->pgsz - scanat;
	}
	if(memchr(&thispage[scanat], 0, scansz))
	    return ptr;
    }
    return NULL;
}

void fmunmap(struct F_MAP *m) {
    void *p = (void *)m;
    size_t len = m->pages * m->pgsz + m->hdrsz;
    munmap(p, len);
}
