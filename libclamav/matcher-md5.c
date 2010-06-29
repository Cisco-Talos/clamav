/*
 *  Copyright (C) 2007-2010 Sourcefire, Inc.
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

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>

#include "clamav.h"
#include "memory.h"
#include "mpool.h"
#include "others.h"
#include "cltypes.h"
#include "matcher.h"
#include "matcher-md5.h"

#define HASH(a,b,c) (211 * a + 37 * b + c)

int cli_md5m_addpatt(struct cli_matcher *root, struct cli_md5m_patt *patt)
{
	unsigned int idx;
	struct cli_md5m_patt *prev, *next = NULL;

    idx = HASH(patt->md5[0], patt->md5[1], patt->md5[2]);
    prev = next = root->md5tab[idx];
    while(next) {
	if(patt->md5[0] >= next->md5[0])
	    break;
	prev = next;
	next = next->next;
    }

    if(next == root->md5tab[idx]) {
	patt->next = root->md5tab[idx];
	root->md5tab[idx] = patt;
    } else {
	patt->next = prev->next;
	prev->next = patt;
    }

    root->md5_patterns++;
    return CL_SUCCESS;
}

int cli_md5m_init(struct cli_matcher *root)
{
#ifdef USE_MPOOL
    if(!root->mempool) {
	cli_errmsg("cli_md5m_init: mempool must be initialized\n");
	return CL_EMEM;
    }
#endif

    if(!(root->md5tab = (struct cli_md5m_patt **) mpool_calloc(root->mempool, HASH(255, 255, 255) + 1, sizeof(struct cli_md5m_patt *)))) {
	mpool_free(root->mempool, root->bm_shift);
	return CL_EMEM;
    }

    return CL_SUCCESS;
}

void cli_md5m_free(struct cli_matcher *root)
{
	struct cli_md5m_patt *patt, *prev;
	unsigned int i, size = HASH(255, 255, 255) + 1;

    if(root->md5tab) {
	for(i = 0; i < size; i++) {
	    patt = root->md5tab[i];
	    while(patt) {
		prev = patt;
		patt = patt->next;
		if(prev->virname)
		    mpool_free(root->mempool, prev->virname);
		mpool_free(root->mempool, prev);
	    }
	}
	mpool_free(root->mempool, root->md5tab);
    }
}

int cli_md5m_scan(const unsigned char *md5, uint32_t filesize, const char **virname, const struct cli_matcher *root)
{
	unsigned int pchain = 0, idx;
	struct cli_md5m_patt *p;

    if(!root)
	return CL_CLEAN;

    idx = HASH(md5[0], md5[1], md5[2]);
    p = root->md5tab[idx];
    if(!p || (!p->next && p->filesize != filesize))
	return CL_CLEAN;

    while(p) {
	if(p->md5[0] != md5[0]) {
	    if(pchain)
		break;
	    p = p->next;
	    continue;
	} else pchain = 1;

	if(p->filesize != filesize) {
	    p = p->next;
	    continue;
	}

	if(!memcmp(p->md5, md5, 16)) {
	    if(virname)
		*virname = p->virname;
	    return CL_VIRUS;
	}
	p = p->next;
    }

    return CL_CLEAN;
}
