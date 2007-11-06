/*
 *  Copyright (C) 2004 - 2005 Tomasz Kojm <tkojm@clamav.net>
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
#include "others.h"
#include "cltypes.h"
#include "matcher.h"
#include "matcher-bm.h"
#include "filetypes.h"

#define BM_MIN_LENGTH	3
#define BM_BLOCK_SIZE	3
#define HASH(a,b,c) (211 * a + 37 * b + c)

int cli_bm_addpatt(struct cli_matcher *root, struct cli_bm_patt *pattern)
{
	uint16_t idx, i;
	const unsigned char *pt = pattern->pattern;
	struct cli_bm_patt *prev, *next = NULL;


    if(pattern->length < BM_MIN_LENGTH) {
	cli_errmsg("Signature for %s is too short\n", pattern->virname);
	return CL_EPATSHORT;
    }

#if BM_MIN_LENGTH == BM_BLOCK_SIZE
    /* try to load balance bm_suffix (at the cost of bm_shift) */
    for(i = 0; i < pattern->length - BM_BLOCK_SIZE + 1; i++) {
	idx = HASH(pt[i], pt[i + 1], pt[i + 2]);
	if(!root->bm_suffix[idx]) {
	    if(i) {
		pattern->prefix = pattern->pattern;
		pattern->prefix_length = i;
		pattern->pattern = &pattern->pattern[i];
		pattern->length -= i;
		pt = pattern->pattern;
	    }
	    break;
	}
    }
#endif

    for(i = 0; i <= BM_MIN_LENGTH - BM_BLOCK_SIZE; i++) {
	idx = HASH(pt[i], pt[i + 1], pt[i + 2]);
	root->bm_shift[idx] = MIN(root->bm_shift[idx], BM_MIN_LENGTH - BM_BLOCK_SIZE - i);
    }

    prev = next = root->bm_suffix[idx];
    while(next) {
	if(pt[0] >= next->pattern[0])
	    break;
	prev = next;
	next = next->next;
    }

    if(next == root->bm_suffix[idx]) {
	pattern->next = root->bm_suffix[idx];
	if(root->bm_suffix[idx])
	    pattern->cnt = root->bm_suffix[idx]->cnt;
	root->bm_suffix[idx] = pattern;
    } else {
	pattern->next = prev->next;
	prev->next = pattern;
    }
    root->bm_suffix[idx]->cnt++;

    return CL_SUCCESS;
}

int cli_bm_init(struct cli_matcher *root)
{
	uint16_t i, size = HASH(255, 255, 255) + 1;


    if(!(root->bm_shift = (uint8_t *) cli_malloc(size * sizeof(uint8_t))))
	return CL_EMEM;

    if(!(root->bm_suffix = (struct cli_bm_patt **) cli_calloc(size, sizeof(struct cli_bm_patt *)))) {
	free(root->bm_shift);
	return CL_EMEM;
    }

    for(i = 0; i < size; i++)
	root->bm_shift[i] = BM_MIN_LENGTH - BM_BLOCK_SIZE + 1;

    return CL_SUCCESS;
}

void cli_bm_free(struct cli_matcher *root)
{
	struct cli_bm_patt *patt, *prev;
	uint16_t i, size = HASH(255, 255, 255) + 1;


    if(root->bm_shift)
	free(root->bm_shift);

    if(root->bm_suffix) {
	for(i = 0; i < size; i++) {
	    patt = root->bm_suffix[i];
	    while(patt) {
		prev = patt;
		patt = patt->next;
		if(prev->prefix)
		    free(prev->prefix);
		else
		    free(prev->pattern);
		if(prev->virname)
		    free(prev->virname);
		if(prev->offset)
		    free(prev->offset);
		free(prev);
	    }
	}
	free(root->bm_suffix);
    }
}

int cli_bm_scanbuff(const unsigned char *buffer, uint32_t length, const char **virname, const struct cli_matcher *root, uint32_t offset, cli_file_t ftype, int fd)
{
	uint32_t i, j, off;
	uint8_t found, pchain, shift;
	uint16_t idx, idxchk;
	struct cli_bm_patt *p;
	const unsigned char *bp, *pt;
	unsigned char prefix;
	struct cli_target_info info;


    if(!root->bm_shift)
	return CL_CLEAN;

    if(length < BM_MIN_LENGTH)
	return CL_CLEAN;

    memset(&info, 0, sizeof(info));

    for(i = BM_MIN_LENGTH - BM_BLOCK_SIZE; i < length - BM_BLOCK_SIZE + 1; ) {
	idx = HASH(buffer[i], buffer[i + 1], buffer[i + 2]);
	shift = root->bm_shift[idx];

	if(shift == 0) {
	    prefix = buffer[i - BM_MIN_LENGTH + BM_BLOCK_SIZE];
	    p = root->bm_suffix[idx];
	    pchain = 0;
	    while(p) {
		if(p->pattern[0] != prefix) {
		    if(pchain)
			break;
		    p = p->next;
		    continue;
		} else pchain = 1;

		off = i - BM_MIN_LENGTH + BM_BLOCK_SIZE;
		bp = buffer + off;

		if((off + p->length > length) || (p->prefix_length > off)) {
		    p = p->next;
		    continue;
		}

		idxchk = MIN(p->length, length - off) - 1;
		if(idxchk) {
		    if((bp[idxchk] != p->pattern[idxchk]) ||  (bp[idxchk / 2] != p->pattern[idxchk / 2])) {
			p = p->next;
			continue;
		    }
		}

		if(p->prefix_length) {
		    off -= p->prefix_length;
		    bp -= p->prefix_length;
		    pt = p->prefix;
		} else {
		    pt = p->pattern;
		}

		found = 1;
		for(j = 0; j < p->length + p->prefix_length && off < length; j++, off++) {
		    if(bp[j] != pt[j]) {
			found = 0;
			break;
		    }
		}

		if(found && p->length + p->prefix_length == j) {

		    if(p->target || p->offset) {
			off = offset + i - p->prefix_length - BM_MIN_LENGTH + BM_BLOCK_SIZE;
			if((fd == -1 && !ftype) || !cli_validatesig(ftype, p->offset, off, &info, fd, p->virname)) {
			    p = p->next;
			    continue;
			}
		    }

		    if(virname)
			*virname = p->virname;

		    if(info.exeinfo.section)
			free(info.exeinfo.section);

		    return CL_VIRUS;
		}

		p = p->next;
	    }

	    shift = 1;
	}

	i += shift;
    }

    if(info.exeinfo.section)
	free(info.exeinfo.section);

    return CL_CLEAN;
}
