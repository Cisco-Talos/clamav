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
#if HAVE_MMAP
#ifdef HAVE_SYS_MMAN_H
#include <sys/mman.h>
#endif
#endif

#include <pthread.h>


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
#define UNPAGE_THRSHLD_LO 4*1024*1024
#define UNPAGE_THRSHLD_HI 8*1024*1024
#define READAHEAD_PAGES 8

/* DON'T ASK ME */
pthread_mutex_t fmap_mutex = PTHREAD_MUTEX_INITIALIZER;


static unsigned int fmap_align_items(unsigned int sz, unsigned int al) {
    return sz / al + (sz % al != 0);
}

static unsigned int fmap_align_to(unsigned int sz, unsigned int al) {
    return al * fmap_align_items(sz, al);
}

static unsigned int fmap_which_page(fmap_t *m, size_t at) {
    return at / m->pgsz;
}


fmap_t *fmap(int fd, off_t offset, size_t len) {
    unsigned int pages, mapsz, hdrsz, dumb = 1;
    int pgsz = cli_getpagesize();
    struct stat st;
    fmap_t *m;

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
    hdrsz = fmap_align_to(sizeof(fmap_t) + pages * sizeof(uint32_t), pgsz);
    mapsz = pages * pgsz + hdrsz;
    pthread_mutex_lock(&fmap_mutex);
#if HAVE_MMAP
    if ((m = (fmap_t *)mmap(NULL, mapsz, PROT_READ | PROT_WRITE, MAP_PRIVATE|/*FIXME: MAP_POPULATE is ~8% faster but more memory intensive */ANONYMOUS_MAP, -1, 0)) == MAP_FAILED) {
	m = NULL;
    } else {
	dumb = 0;
	madvise(m, mapsz, MADV_RANDOM|MADV_DONTFORK);
    }
#else
    m = (fmap_t *)cli_malloc(mapsz);
#endif
    if(!m) {
	cli_warnmsg("fmap: map allocation failed\n");
	pthread_mutex_unlock(&fmap_mutex);
	return NULL;
    }
    /* fault the header while we still have the lock - we DO context switch here a lot here :@ */
    memset(m->bitmap, 0, sizeof(uint32_t) * pages);
    pthread_mutex_unlock(&fmap_mutex);
    m->fd = fd;
    m->dumb = dumb;
    m->mtime = st.st_mtime;
    m->offset = offset;
    m->len = len;
    m->pages = pages;
    m->hdrsz = hdrsz;
    m->pgsz = pgsz;
    m->paged = 0;
#ifdef FMAPDEBUG
    m->page_needs = 0;
    m->page_reads = 0;
    m->page_locks = 0;
    m->page_unlocks = 0;
    m->page_unmaps = 0;
#endif
    return m;
}


static void fmap_aging(fmap_t *m) {
#if HAVE_MMAP
    if(m->dumb) return;
    if(m->paged * m->pgsz > UNPAGE_THRSHLD_HI) { /* we alloc'd too much */
	unsigned int i, avail = 0, freeme[2048], maxavail = MIN(sizeof(freeme)/sizeof(*freeme), m->paged - UNPAGE_THRSHLD_LO / m->pgsz) - 1;

	for(i=0; i<m->pages; i++) {
	    uint32_t s = m->bitmap[i];
	    if((s & (FM_MASK_PAGED | FM_MASK_LOCKED)) == FM_MASK_PAGED ) {
		/* page is paged and not locked: dec age */
		if(s & FM_MASK_COUNT) m->bitmap[i]--;
		/* and make it available for unpaging */

		if(!avail) {
		    freeme[0] = i;
		    avail++;
		} else {
		    /* Insert sort onto a stack'd array - same performance as quickselect */
		    unsigned int insert_to = MIN(maxavail, avail) - 1, age = m->bitmap[i] & FM_MASK_COUNT;
		    if(avail <= maxavail || m->bitmap[freeme[maxavail]] & FM_MASK_COUNT > age) {
			while(m->bitmap[freeme[insert_to]] & FM_MASK_COUNT > age) {
			    freeme[insert_to + 1] = freeme[insert_to];
			    if(!insert_to--) break;
			}
			freeme[insert_to + 1] = i;
			if(avail <= maxavail) avail++;
		    }
		}
	    }
	}
	if(avail) { /* at least one page is paged and not locked */
	    for(i=0; i<avail; i++) {
		char *pptr = (char *)m + i * m->pgsz + m->hdrsz;
		/* we mark the page as seen */
		m->bitmap[freeme[i]] = FM_MASK_SEEN;
		/* and we mmap the page over so the kernel knows there's nothing good in there */
		pthread_mutex_lock(&fmap_mutex);
		if(mmap(pptr, m->pgsz, PROT_READ | PROT_WRITE, MAP_FIXED|MAP_PRIVATE|ANONYMOUS_MAP, -1, 0) == MAP_FAILED)
		    cli_warnmsg("fmap_aging: kernel hates you\n");
		pthread_mutex_unlock(&fmap_mutex);
	    }
	    m->paged -= avail;
#ifdef FMAPDEBUG
	    m->page_unmaps += avail;
#endif
	}
    }
#endif
}


static int fmap_readpage(fmap_t *m, unsigned int first_page, unsigned int count, unsigned int lock_count) {
    size_t readsz = 0, got;
    char *pptr = NULL;
    uint32_t s;
    unsigned int i, page = first_page, force_read = 0;

    pthread_mutex_lock(&fmap_mutex);
    for(i=0; i<count; i++) { /* prefault */
    	/* Not worth checking if the page is already paged, just ping each */
	/* Also not worth reusing the loop below */
    	volatile char faultme = ((char *)m)[(first_page+i) * m->pgsz + m->hdrsz];
    }
    pthread_mutex_unlock(&fmap_mutex);
#ifdef FMAPDEBUG
    m->page_needs += count;
    m->page_locks += lock_count;
#endif
    for(i=0; i<=count; i++, page++) {
	int lock;
	if(lock_count) {
	    lock_count--;
	    lock = 1;
	} else lock = 0;
	if(i == count) {
	    /* we count one page too much to flush pending reads */
	    if(!pptr) return 0; /* if we have any */
	    force_read = 1;
	} else if((s=m->bitmap[page]) & FM_MASK_PAGED) {
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
	    if(!pptr) continue;
	    force_read = 1;
	}

	if(force_read) {
	    /* we have some pending reads to perform */
	    unsigned int j;
	    for(j=first_page; j<page; j++) {
		if(m->bitmap[j] & FM_MASK_SEEN) {
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
		    break;
		}
	    }

	    if((got=pread(m->fd, pptr, readsz, m->offset + first_page * m->pgsz)) != readsz) {
		cli_warnmsg("pread fail: page %u pages %u map-offset %lu - asked for %lu bytes, got %lu\n", first_page, m->pages, (long unsigned int)m->offset, (long unsigned int)readsz, (long unsigned int)got);
		return 1;
	    }
#ifdef FMAPDEBUG
	    m->page_reads += count;
#endif
	    pptr = NULL;
	    force_read = 0;
	    readsz = 0;
	    continue;
	}

	/* page is not already paged */
	if(!pptr) {
	    /* set a new start for pending reads if we don't have one */
	    pptr = (char *)m + page * m->pgsz + m->hdrsz;
	    first_page = page;
	}
	if((page == m->pages - 1) && (m->len % m->pgsz))
	    readsz += m->len % m->pgsz;
	else
	    readsz += m->pgsz;
	if(lock) /* lock requested: set paged, lock page and set lock count to 1 */
	    m->bitmap[page] = FM_MASK_PAGED | FM_MASK_LOCKED | 1;
	else /* no locking: set paged and set aging to max */
	    m->bitmap[page] = FM_MASK_PAGED | FM_MASK_COUNT;
	m->paged++;
    }
    return 0;
}


static void *fmap_need(fmap_t *m, size_t at, size_t len, int lock) {
    unsigned int first_page, last_page, lock_count;
    char *ret;

    if(!len) {
//	cli_warnmsg("fmap: attempted void need\n");
	return NULL;
    }

    if(!CLI_ISCONTAINED(0, m->len, at, len)) {
      //	cli_warnmsg("fmap: attempted oof need\n");
	return NULL;
    }

    fmap_aging(m);

    first_page = fmap_which_page(m, at);
    last_page = fmap_which_page(m, at + len - 1);
    lock_count = (lock!=0) * (last_page-first_page+1);
#ifdef READAHED_PAGES
    last_page += READAHED_PAGES;
    if(last_page >= m->pages) last_page = m->pages - 1;
#endif

    if(fmap_readpage(m, first_page, last_page-first_page+1, lock_count))
	return NULL;

    ret = (char *)m;
    ret += at + m->hdrsz;
    return (void *)ret;
}

void *fmap_need_off(fmap_t *m, size_t at, size_t len) {
    return fmap_need(m, at, len, 1);
}
void *fmap_need_off_once(fmap_t *m, size_t at, size_t len) {
    return fmap_need(m, at, len, 0);
}
void *fmap_need_ptr(fmap_t *m, void *ptr, size_t len) {
    return fmap_need_off(m, (char *)ptr - (char *)m - m->hdrsz, len);
}
void *fmap_need_ptr_once(fmap_t *m, void *ptr, size_t len) {
    return fmap_need_off_once(m, (char *)ptr - (char *)m - m->hdrsz, len);
}

void *fmap_need_str(fmap_t *m, void *ptr, size_t len_hint) {
    size_t at = (char *)ptr - (char *)m - m->hdrsz;
    return fmap_need_offstr(m, at, len_hint);
}

static void fmap_unneed_page(fmap_t *m, unsigned int page) {
    uint32_t s = m->bitmap[page];

    if((s & (FM_MASK_PAGED | FM_MASK_LOCKED)) == (FM_MASK_PAGED | FM_MASK_LOCKED)) {
	/* page is paged and locked: check lock count */
	s &= FM_MASK_COUNT;
#ifdef FMAPDEBUG
	m->page_unlocks ++;
#endif
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

void fmap_unneed_off(fmap_t *m, size_t at, size_t len) {
    unsigned int i, first_page, last_page;
    if(m->dumb) return;
    if(!len) {
	cli_warnmsg("fmap_unneed: attempted void unneed\n");
	return;
    }

    if(!CLI_ISCONTAINED(0, m->len, at, len)) {
	cli_warnmsg("fmap: attempted oof unneed\n");
	return;
    }

//    cli_errmsg("FMAPDBG: unneed_off map %p at %u len %u\n", m, at, len);

    first_page = fmap_which_page(m, at);
    last_page = fmap_which_page(m, at + len - 1);

    for(i=first_page; i<=last_page; i++) {
	fmap_unneed_page(m, i);
    }
}

void fmap_unneed_ptr(fmap_t *m, void *ptr, size_t len) {
//    cli_errmsg("FMAPDBG: unneed_ptr map %p at %p len %u\n", m, ptr, len);
    fmap_unneed_off(m, (char *)ptr - (char *)m - m->hdrsz, len);
}

int fmap_readn(fmap_t *m, void *dst, size_t at, size_t len) {
    char *src;

    if(at > m->len)
	return -1;
    if(len > m->len - at)
	len = m->len - at;
    src = fmap_need_off_once(m, at, len);
    if(!src)
	return -1;
    memcpy(dst, src, len);
    return len;
}

void funmap(fmap_t *m) {
#ifdef FMAPDEBUG
  cli_errmsg("FMAPDEBUG: Needs:%u reads:%u locks:%u unlocks:%u unmaps:%u\n", m->page_needs, m->page_reads, m->page_locks, m->page_unlocks, m->page_unmaps);
#endif

#if HAVE_MMAP
    if(!m->dumb) {
	size_t len = m->pages * m->pgsz + m->hdrsz;
	pthread_mutex_lock(&fmap_mutex);
	munmap((void *)m, len);
	pthread_mutex_unlock(&fmap_mutex);
    } else
#endif
	free((void *)m);
}

void *fmap_need_offstr(fmap_t *m, size_t at, size_t len_hint) {
    unsigned int i, first_page, last_page;
    void *ptr = (void *)((char *)m + m->hdrsz + at);

    if(!len_hint || len_hint > m->len - at)
	len_hint = m->len - at;

    if(!CLI_ISCONTAINED(0, m->len, at, len_hint)) {
      //	cli_warnmsg("fmap: attempted oof need_str\n");
	return NULL;
    }

    fmap_aging(m);

    first_page = fmap_which_page(m, at);
    last_page = fmap_which_page(m, at + len_hint - 1);

    for(i=first_page; i<=last_page; i++) {
	char *thispage = (char *)m + m->hdrsz + i * m->pgsz;
	unsigned int scanat, scansz;

	if(fmap_readpage(m, i, 1, 1)) {
	    last_page = i-1;
	    break;
	}
	if(i == first_page) {
	    scanat = at % m->pgsz;
	    scansz = MIN(len_hint, m->pgsz - scanat);
	} else {
	    scanat = 0;
	    scansz = MIN(len_hint, m->pgsz);
	}
	len_hint -= scansz;
	if(memchr(&thispage[scanat], 0, scansz))
	    return ptr;
    }
    for(i=first_page; i<=last_page; i++)
	fmap_unneed_page(m, i);
    return NULL;
}


void *fmap_gets(fmap_t *m, char *dst, size_t *at, size_t max_len) {
    unsigned int i, first_page, last_page;
    char *src = (void *)((char *)m + m->hdrsz + *at), *endptr = NULL;
    size_t len = MIN(max_len-1, m->len - *at), fullen = len;

    if(!len || !CLI_ISCONTAINED(0, m->len, *at, len)) {
        //cli_warnmsg("fmap: attempted oof need_str\n");
	return NULL;
    }

    fmap_aging(m);

    first_page = fmap_which_page(m, *at);
    last_page = fmap_which_page(m, *at + len - 1);

    for(i=first_page; i<=last_page; i++) {
	char *thispage = (char *)m + m->hdrsz + i * m->pgsz;
	unsigned int scanat, scansz;

	if(fmap_readpage(m, i, 1, 0))
	    return NULL;

	if(i == first_page) {
	    scanat = *at % m->pgsz;
	    scansz = MIN(len, m->pgsz - scanat);
	} else {
	    scanat = 0;
	    scansz = MIN(len, m->pgsz);
	}
	len -= scansz;

	if((endptr = memchr(&thispage[scanat], '\n', scansz))) {
	    endptr++;
	    break;
	}
    }
    if(endptr) {
	memcpy(dst, src, endptr - src);
	dst[endptr - src] = '\0';
	*at += endptr - src;
    } else {
	memcpy(dst, src, fullen);
	dst[fullen] = '\0';
	*at += fullen;
    }
    return dst;
}
