/*
 *  Copyright (C) 2004 Tomasz Kojm <tkojm@clamav.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "clamav.h"
#include "memory.h"
#include "others.h"
#include "cltypes.h"

#define BM_MIN_LENGTH 10
#define BM_BLOCK_SIZE 3

#define MIN(a,b) (a < b) ? a : b


int cli_bm_addpatt(struct cl_node *root, struct cli_bm_patt *pattern)
{
	int i;
	uint16_t idx;
	const char *pt = pattern->pattern;
	struct cli_bm_patt *prev, *next = NULL;


    if(pattern->length < BM_MIN_LENGTH) {
	cli_dbgmsg("Ignoring signature for %s (too short)\n", pattern->virname);
	/* return CL_EPATSHORT; */
	return 0;
    }

    for(i = BM_MIN_LENGTH - BM_BLOCK_SIZE; i >= 0; i--) {
	idx = 211 * ((unsigned char) pt[i]) + 37 * ((unsigned char) pt[i + 1]) + (unsigned char) pt[i + 2];
	root->bm_shift[idx] = MIN(root->bm_shift[idx], BM_MIN_LENGTH - BM_BLOCK_SIZE - i);
    }

    i = BM_MIN_LENGTH - BM_BLOCK_SIZE;
    idx = 211 * ((unsigned char) pt[i]) + 37 * ((unsigned char) pt[i + 1]) + (unsigned char) pt[i + 2];

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

int cli_bm_init(struct cl_node *root)
{
	int i;


    cli_dbgmsg("in cli_bm_init()\n");

    if(!(root->bm_shift = (int *) cli_malloc(65536 * sizeof(int))))
	return CL_EMEM;

    if(!(root->bm_suffix = (struct cli_bm_patt **) cli_calloc(65536, sizeof(struct cli_bm_patt *)))) {
	free(root->bm_shift);
	return CL_EMEM;
    }

    for(i = 0; i < 65536; i++)
	root->bm_shift[i] = BM_MIN_LENGTH - BM_BLOCK_SIZE + 1;

    return 0;
}

void cli_bm_free(struct cl_node *root)
{
	struct cli_bm_patt *b1, *b2;
	int i;


    if(root->bm_shift)
	free(root->bm_shift);

    if(root->bm_suffix) {
	for(i = 0; i < 65536; i++) {
	    b1 = root->bm_suffix[i];
	    while(b1) {
		b2 = b1;
		b1 = b1->next;
		if(b2->virname)
		    free(b2->virname);
		if(b2->pattern)
		    free(b2->pattern);
		free(b2);
	    }
	}
	free(root->bm_suffix);
    }
}

int cli_bm_scanbuff(const char *buffer, unsigned int length, const char **virname, const struct cl_node *root)
{
	int i, j, shift, off, found = 0;
	uint16_t idx;
	struct cli_bm_patt *p;
	const char *bp;
	char prefix;


    if(length < BM_MIN_LENGTH)
	return CL_CLEAN;

    for(i = BM_MIN_LENGTH - BM_BLOCK_SIZE; i < length - BM_BLOCK_SIZE + 1; ) {
	idx = 211 * ((unsigned char) buffer[i]) + 37 * ((unsigned char) buffer[i + 1]) + (unsigned char) buffer[i + 2];

	shift = root->bm_shift[idx];

	if(shift == 0) {

	    prefix = buffer[i - BM_MIN_LENGTH + BM_BLOCK_SIZE];
	    p = root->bm_suffix[idx];

	    while(p && p->pattern[0] != prefix)
		p = p->next;

	    while(p && p->pattern[0] == prefix) {
		off = i - BM_MIN_LENGTH + BM_BLOCK_SIZE;
		bp = buffer + off;
		found = 1;
		for(j = 0; j < p->length && off < length; j++, off++) {
		    if(bp[j] != p->pattern[j]) {
			found = 0;
			break;
		    }
		}

		if(found && p->length == j) {
		    if(virname)
			*virname = p->virname;

		    return CL_VIRUS;
		}

		p = p->next;
	    }

	    shift = 1;
	}

	i += shift;
    }

    return 0;
}
