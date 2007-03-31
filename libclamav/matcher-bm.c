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

/* TODO: Check prefix regularity and automatically transfer some signatures
 *	 to AC
 */

#define BM_MIN_LENGTH	3
/* #define BM_TEST_OFFSET	5 */
#define BM_BLOCK_SIZE	3

#define HASH(a,b,c) (211 * a + 37 * b + c)


int cli_bm_addpatt(struct cli_matcher *root, struct cli_bm_patt *pattern)
{
	int i;
	uint16_t idx;
	const unsigned char *pt = pattern->pattern;
	struct cli_bm_patt *prev, *next = NULL;


    if(pattern->length < BM_MIN_LENGTH) {
	cli_errmsg("Signature for %s is too short\n", pattern->virname);
	return CL_EPATSHORT;
    }

    for(i = BM_MIN_LENGTH - BM_BLOCK_SIZE; i >= 0; i--) {
	idx = HASH(pt[i], pt[i + 1], pt[i + 2]);
	root->bm_shift[idx] = MIN(root->bm_shift[idx], BM_MIN_LENGTH - BM_BLOCK_SIZE - i);
    }

    i = BM_MIN_LENGTH - BM_BLOCK_SIZE;
    idx = HASH(pt[i], pt[i + 1], pt[i + 2]);

    prev = next = root->bm_suffix[idx];

    while(next) {
	if(pt[0] >= next->pattern[0])
	    break;
	prev = next;
	next = next->next;
    }

    if(next == root->bm_suffix[idx]) {
	pattern->next = root->bm_suffix[idx];
	root->bm_suffix[idx] = pattern;
    } else {
	pattern->next = prev->next;
	prev->next = pattern;
    }

    return 0;
}

int cli_bm_init(struct cli_matcher *root)
{
	unsigned int i;
	unsigned int size = HASH(256, 256, 256);


    cli_dbgmsg("in cli_bm_init()\n");
    cli_dbgmsg("BM: Number of indexes = %d\n", size);

    if(!(root->bm_shift = (int *) cli_malloc(size * sizeof(int))))
	return CL_EMEM;

    if(!(root->bm_suffix = (struct cli_bm_patt **) cli_calloc(size, sizeof(struct cli_bm_patt *)))) {
	free(root->bm_shift);
	return CL_EMEM;
    }

    for(i = 0; i < size; i++)
	root->bm_shift[i] = BM_MIN_LENGTH - BM_BLOCK_SIZE + 1;

    return 0;
}

void cli_bm_free(struct cli_matcher *root)
{
	struct cli_bm_patt *b1, *b2;
	unsigned int i;
	unsigned int size = HASH(256, 256, 256);


    if(root->bm_shift)
	free(root->bm_shift);

    if(root->bm_suffix) {
	for(i = 0; i < size; i++) {
	    b1 = root->bm_suffix[i];
	    while(b1) {
		b2 = b1;
		b1 = b1->next;
		if(b2->virname)
		    free(b2->virname);
		if(b2->offset)
		    free(b2->offset);
		if(b2->pattern)
		    free(b2->pattern);
		free(b2);
	    }
	}
	free(root->bm_suffix);
    }
}

int cli_bm_scanbuff(const unsigned char *buffer, uint32_t length, const char **virname, const struct cli_matcher *root, uint32_t offset, cli_file_t ftype, int fd)
{
	unsigned int i, j, shift, off, found = 0;
	int idxtest;
	uint16_t idx;
	struct cli_bm_patt *p;
	const unsigned char *bp;
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

	    while(p && p->pattern[0] != prefix)
		p = p->next;

	    while(p && p->pattern[0] == prefix) {
		off = i - BM_MIN_LENGTH + BM_BLOCK_SIZE;
		bp = buffer + off;

#ifdef BM_TEST_OFFSET
		if(bp[BM_TEST_OFFSET] != p->pattern[BM_TEST_OFFSET]) {
		    p = p->next;
		    continue;
		}
#endif

		idxtest = MIN (p->length, length - off ) - 1;
		if(idxtest >= 0) {
		    if(bp[idxtest] != p->pattern[idxtest]) {
			p = p->next;
			continue;
		    }
		}

		found = 1;
		for(j = 0; j < p->length && off < length; j++, off++) {
		    if(bp[j] != p->pattern[j]) {
			found = 0;
			break;
		    }
		}

		if(found && p->length == j) {

		    if(p->target || p->offset) {
			off = offset + i - BM_MIN_LENGTH + BM_BLOCK_SIZE;

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
