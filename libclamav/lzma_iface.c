/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: aCaB
 * 
 *  Acknowledgements: This contains an implementation of the LZMA algorithm 
 *                    from Igor Pavlov (see COPYING.lzma).
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

/* zlib-alike state interface to LZMA */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include "clamav.h"
#include "lzma_iface.h"

void *__lzma_wrap_alloc(void *unused, size_t size) { 
    UNUSEDPARAM(unused);
    if(!size || size > CLI_MAX_ALLOCATION)
	return NULL;
    if(!size || size > CLI_MAX_ALLOCATION) {
	cli_dbgmsg("lzma_wrap_alloc(): Attempt to allocate %lu bytes.\n", (unsigned long int) size);
	return NULL;
    }

    return cli_calloc(1, size);
}
void __lzma_wrap_free(void *unused, void *freeme) {
    UNUSEDPARAM(unused);
    free(freeme);
}
static ISzAlloc g_Alloc = { __lzma_wrap_alloc, __lzma_wrap_free };


static unsigned char lzma_getbyte(struct CLI_LZMA *L, int *fail) {
    unsigned char c;
    if(!L->next_in || !L->avail_in) {
	*fail = 1;
	return 0;
    }
    *fail = 0;
    c = L->next_in[0];
    L->next_in++;
    L->avail_in--;
    return c;
}
    

int cli_LzmaInit(struct CLI_LZMA *L, uint64_t size_override) {
    int fail;

    if(!L->init) {
	L->p_cnt = LZMA_PROPS_SIZE;
	if(size_override)
	    L->usize = size_override;
	else
	    L->s_cnt = 8;
	L->init = 1;
    } else if(size_override)
	cli_warnmsg("cli_LzmaInit: ignoring late size override\n");

    if(L->freeme) return LZMA_RESULT_OK;

    while(L->p_cnt) {
	L->header[LZMA_PROPS_SIZE - L->p_cnt] = lzma_getbyte(L, &fail);
	if(fail) return LZMA_RESULT_OK;
	L->p_cnt--;
    }

    while(L->s_cnt) {
	uint64_t c = (uint64_t)lzma_getbyte(L, &fail);
	if(fail) return LZMA_RESULT_OK;
	L->usize = c << (8 * (8 - L->s_cnt));
	L->s_cnt--;
    }

    LzmaDec_Construct(&L->state);
    if(LzmaDec_Allocate(&L->state, L->header, LZMA_PROPS_SIZE, &g_Alloc) != SZ_OK)
	return LZMA_RESULT_DATA_ERROR;
    LzmaDec_Init(&L->state);

    L->freeme = 1;
    return LZMA_RESULT_OK;
}
	

void cli_LzmaShutdown(struct CLI_LZMA *L) {
    if(L->freeme)
	LzmaDec_Free(&L->state, &g_Alloc);
    return;
}


int cli_LzmaDecode(struct CLI_LZMA *L) {
    SRes res;
    SizeT outbytes, inbytes;
    ELzmaStatus status;
    ELzmaFinishMode finish;

    if(!L->freeme) return cli_LzmaInit(L, 0);

    inbytes = L->avail_in;
    if(~L->usize && L->avail_out > L->usize) {
	outbytes = L->usize;
	finish = LZMA_FINISH_END;
    } else {
	outbytes = L->avail_out;
	finish = LZMA_FINISH_ANY;
    }
    res = LzmaDec_DecodeToBuf(&L->state, L->next_out, &outbytes, L->next_in, &inbytes, finish, &status);
    L->avail_in -= inbytes;
    L->next_in += inbytes;
    L->avail_out -= outbytes;
    L->next_out += outbytes;
    if(~L->usize) L->usize -= outbytes;
    if(res != SZ_OK)
	return LZMA_RESULT_DATA_ERROR;
    if(!L->usize || status == LZMA_STATUS_FINISHED_WITH_MARK)
	return LZMA_STREAM_END;
    return LZMA_RESULT_OK;
}
