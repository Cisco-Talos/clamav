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

#define _XOPEN_SOURCE 500
#define _BSD_SOURCE

#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

#include "others.h"
#include "cltypes.h"

#define FM_MASK_COUNT 0x3fffffff
#define FM_MASK_PAGED 0x40000000
#define FM_MASK_SEEN 0x80000000
#define FM_MASK_LOCKED FM_MASK_SEEN
/* 2 high bits:
00 - not seen - not paged - N/A
01 -    N/A   -   paged   - not locked
10 -   seen   - not paged - N/A
11 -    N/A   -   paged   - locked
*/

/* FIXME: tune this stuff */
#define UNPAGE_THRSHLD_HI 1*1024*1024
#define UNPAGE_THRSHLD_LO 4*1024*1024

struct F_MAP {
    int fd;
    time_t mtime;
    size_t offset;
    size_t len;
    unsigned int pages;
    unsigned int hdrsz;
    unsigned int pgsz;
    unsigned int paged;
    uint32_t bitmap[]; /* FIXME: do not use flexible arrays */
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
    hdrsz = fmap_align_to(sizeof(struct F_MAP) + pages * sizeof(uint32_t), pgsz);
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
    m->paged = 0;
    memset(m->bitmap, 0, sizeof(uint32_t) * pages);
    cli_errmsg("FMAPDBG: created %p - len %u pages %u hdrsz %u\n", m, len, pages, hdrsz);
    return m;
}


static void fmap_qsel(struct F_MAP *m, unsigned int *freeme, unsigned int left, unsigned int right) {
    unsigned int i = left, j = right;
    unsigned int pivot = m->bitmap[freeme[(left + right) / 2]] & FM_MASK_COUNT;

    while(i <= j) {
	while((m->bitmap[freeme[i]] & FM_MASK_COUNT) > pivot)
	    i++;
	while((m->bitmap[freeme[j]] & FM_MASK_COUNT) < pivot)
	    j--;
	if(i <= j) {
	    unsigned int temp = freeme[i];
	    freeme[i] = freeme[j];
	    freeme[j] = temp;
	    i++;
	    j--;
	}
    }

    if(left < j)
	fmap_qsel(m, freeme, left, j);
    if(i < right)
	fmap_qsel(m, freeme, i, right);
}


static void fmap_aging(struct F_MAP *m) {
    if(m->paged * m->pgsz > UNPAGE_THRSHLD_LO) { /* we alloc'd too much */
	unsigned int i, avail = 0, *freeme;
	freeme = cli_malloc(sizeof(unsigned int) * m->pages);
	if(!freeme) return;
	for(i=0; i<m->pages; i++) {
	    uint32_t s = m->bitmap[i];
	    if((s & (FM_MASK_PAGED | FM_MASK_LOCKED)) == FM_MASK_PAGED ) {
		/* page is paged and not locked: dec age */
		if(s & FM_MASK_COUNT) m->bitmap[i]--;
		/* and make it available for unpaging */
		freeme[avail] = i;
		avail++;
	    }
	}
	if(avail) { /* at least one page is paged and not locked */
	    if(avail * m->pgsz > UNPAGE_THRSHLD_HI ) {
		/* if we've got more unpageable pages than we need, we pick the oldest */
		fmap_qsel(m, freeme, 0, avail - 1);
		avail = UNPAGE_THRSHLD_HI % m->pgsz;
	    }
	    for(i=0; i<avail; i++) {
		char *pptr = (char *)m + i * m->pgsz + m->hdrsz;
		/* we mark the page as seen */
		m->bitmap[freeme[i]] = FM_MASK_SEEN;
		m->paged--;
		/* and we mmap the page over so the kernel knows there's nothing good in there */
		if(mmap(pptr, m->pgsz, PROT_READ | PROT_WRITE, MAP_FIXED|MAP_PRIVATE|ANONYMOUS_MAP, -1, 0) == MAP_FAILED)
		    cli_warnmsg("fmap_aging: kernel hates you\n");
	    }
	}
	free(freeme);
    }
}


static int fmap_readpage(struct F_MAP *m, unsigned int page, int lock) {
    size_t readsz, got;
    char *pptr;
    uint32_t s = m->bitmap[page];

    if(s & FM_MASK_PAGED) {
	/* page already paged */
	if(lock) {
	    /* we want locking */
	    if(s & FM_MASK_LOCKED) {
		/* page already locked */
		s &= FM_MASK_COUNT;
		if(s == FM_MASK_COUNT) { /* lock count already at max: fial! */
		    cli_errmsg("fmap_readpage: lock count exceeded\n");
		    return 1;
		}
		/* acceptable lock count: inc lock count */
		m->bitmap[page]++;
	    } else /* page not currently locked: set lock count = 1 */
		m->bitmap[page] = 1 | FM_MASK_LOCKED | FM_MASK_PAGED;
	} else {
	    /* we don't want locking */
	    if(!(s & FM_MASK_LOCKED)) {
		/* page is not locked: we reset aging to max */
		m->bitmap[page] = FM_MASK_PAGED | FM_MASK_COUNT;
	    }
	}
	return 0;
    }

    /* page is not already paged */
    pptr = (char *)m + page * m->pgsz + m->hdrsz;
    if(page == m->pages - 1)
	readsz = m->len % m->pgsz;
    else
	readsz = m->pgsz;
    if(s & FM_MASK_SEEN) {
	/* page we've seen before: check mtime */
	struct stat st;

	if(fstat(m->fd, &st)) {
	    cli_warnmsg("fmap_readpage: fstat failed\n");
	    return 1;
	}
	if(m->mtime != st.st_mtime) {
	    cli_warnmsg("fmap_readpage: file changed as we read it\n");
	    return 1;
	}
    }
    if((got=pread(m->fd, pptr, readsz, m->offset + page * m->pgsz)) != readsz) {
	cli_warnmsg("pread fail: page %u pages %u map-offset %lu - asked for %lu bytes, got %lu\n", page, m->pages, (long unsigned int)m->offset, (long unsigned int)readsz, (long unsigned int)got);
	return 1;
    }

    if(lock) /* lock requested: set paged, lock page and set lock count to 1 */
	m->bitmap[page] = FM_MASK_PAGED | FM_MASK_LOCKED | 1;
    else /* no locking: set paged and set aging to max */
	m->bitmap[page] = FM_MASK_PAGED | FM_MASK_COUNT;
    m->paged++;
    return 0;
}


static void *fmap_need(struct F_MAP *m, size_t at, size_t len, int lock) {
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

    fmap_aging(m);

    first_page = fmap_which_page(m, at);
    last_page = fmap_which_page(m, at + len - 1);

    cli_errmsg("FMAPDBG: +++ map %p - len %u lock: %d (page %u to %u)\n", m, len, lock, first_page, last_page);

    for(i=first_page; i<=last_page; i++) {
	if(fmap_readpage(m, i, lock))
	    return NULL;
    }

    ret = (char *)m;
    ret += at + m->hdrsz;
    return (void *)ret;
}

void *fmap_need_off(struct F_MAP *m, size_t at, size_t len) {
    cli_errmsg("FMAPDBG: need_off map %p at %u len %u\n", m, at, len);
    return fmap_need(m, at, len, 1);
}
void *fmap_need_off_once(struct F_MAP *m, size_t at, size_t len) {
    cli_errmsg("FMAPDBG: need_off_once map %p at %u len %u\n", m, at, len);
    return fmap_need(m, at, len, 0);
}
void *fmap_need_ptr(struct F_MAP *m, void *ptr, size_t len) {
    cli_errmsg("FMAPDBG: need_ptr map %p at %p len %u\n", m, ptr, len);
    return fmap_need_off(m, (char *)ptr - (char *)m - m->hdrsz, len);
}
void *fmap_need_ptr_once(struct F_MAP *m, void *ptr, size_t len) {
    cli_errmsg("FMAPDBG: need_ptr_once map %p at %p len %u\n", m, ptr, len);
    return fmap_need_off_once(m, (char *)ptr - (char *)m - m->hdrsz, len);
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

    cli_errmsg("FMAPDBG: need_str map %p at %p len %u\n", m, ptr, len);
    first_page = fmap_which_page(m, at);
    last_page = fmap_which_page(m, at + len - 1);

    for(i=first_page; i<=last_page; i++) {
	char *thispage = (char *)m + m->hdrsz + i * m->pgsz;
	unsigned int scanat, scansz;

	cli_errmsg("FMAPDBG: +s+ map %p - (page %u)\n", m, i);

	if(fmap_readpage(m, i, 1))
	    return NULL;
	if(i == first_page) {
	    scanat = at % m->pgsz;
	    scansz = m->pgsz - scanat;
	} else {
	    scanat = 0;
	    scansz = m->pgsz;
	}
	if(memchr(&thispage[scanat], 0, scansz))
	    return ptr;
    }
    return NULL;
}


static void fmap_unneed_page(struct F_MAP *m, unsigned int page) {
    uint32_t s = m->bitmap[page];

    cli_errmsg("FMAPDBG: --- map %p - page %u status %u count %u\n", m, page, s>>30, s & FM_MASK_COUNT);

    if((s & (FM_MASK_PAGED | FM_MASK_LOCKED)) == (FM_MASK_PAGED | FM_MASK_LOCKED)) {
	/* page is paged and locked: check lock count */
	s &= FM_MASK_COUNT;
	if(s > 1) /* locked more than once: dec lock count */
	    m->bitmap[page]--;
	else if (s == 1) /* only one lock left: unlock and begin aging */
	    m->bitmap[page] = FM_MASK_COUNT | FM_MASK_PAGED;
	else 
	    cli_errmsg("fmap_unneed: inconsistent map state\n");
	return;
    }
    cli_warnmsg("fmap_unneed: unneed on a unlocked page\n");
    return;
}

void fmap_unneed_off(struct F_MAP *m, size_t at, size_t len) {
    unsigned int i, first_page, last_page;
    if(!len) {
	cli_warnmsg("fmap_unneed: attempted void unneed\n");
	return;
    }

    if(!CLI_ISCONTAINED(0, m->len, at, len)) {
	cli_warnmsg("fmap: attempted oof need\n");
	return;
    }

    cli_errmsg("FMAPDBG: unneed_off map %p at %u len %u\n", m, at, len);

    first_page = fmap_which_page(m, at);
    last_page = fmap_which_page(m, at + len - 1);

    for(i=first_page; i<=last_page; i++) {
	fmap_unneed_page(m, i);
    }
}

void fmap_unneed_ptr(struct F_MAP *m, void *ptr, size_t len) {
    cli_errmsg("FMAPDBG: unneed_ptr map %p at %p len %u\n", m, ptr, len);
    return fmap_unneed_off(m, (char *)ptr - (char *)m - m->hdrsz, len);
}

void fmunmap(struct F_MAP *m) {
    void *p = (void *)m;
    size_t len = m->pages * m->pgsz + m->hdrsz;
    munmap(p, len);
}
