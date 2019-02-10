/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2013 Sourcefire, Inc.
 *
 *  Authors: Steven Morgan (smorgan@sourcefire.com)
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

#include "clamav.h"
#include "7z/XzCrc64.h"
#include "xz_iface.h"

void *__xz_wrap_alloc(void *unused, size_t size);
void __xz_wrap_free(void *unused, void *freeme);

void *__xz_wrap_alloc(void *unused, size_t size) {
    UNUSEDPARAM(unused);
    if(!size || size > CLI_MAX_ALLOCATION)
	return NULL;
    if(!size || size > CLI_MAX_ALLOCATION) {
	cli_dbgmsg("xz_iface: Attempt to allocate %lu bytes exceeds CLI_MAX_ALLOCATION.\n",
                   (unsigned long int) size);
	return NULL;
    }
    return cli_malloc(size);
}
void __xz_wrap_free(void *unused, void *freeme) {
    UNUSEDPARAM(unused);
    free(freeme);
}

static ISzAlloc g_Alloc = { __xz_wrap_alloc, __xz_wrap_free };
    
int cli_XzInit(struct CLI_XZ *XZ) {
    if (SZ_OK != XzUnpacker_Create(&XZ->state, &g_Alloc))
        return XZ_RESULT_DATA_ERROR;
    if (g_Crc64Table[1] == 0)
        Crc64GenerateTable();
    return XZ_RESULT_OK;
}
	
void cli_XzShutdown(struct CLI_XZ *XZ) {
    if (!XZ)
        return;
    XzUnpacker_Free(&XZ->state);
}

int cli_XzDecode(struct CLI_XZ *XZ) {
    SRes res;
    SizeT outbytes, inbytes;

    inbytes = XZ->avail_in;
    outbytes = XZ->avail_out;
    res = XzUnpacker_Code(&XZ->state, XZ->next_out, &outbytes, 
                          XZ->next_in, &inbytes, CODER_FINISH_ANY, &XZ->status);
    XZ->avail_in -= inbytes;
    XZ->next_in += inbytes;
    XZ->avail_out -= outbytes;
    XZ->next_out += outbytes;
    if (XZ->status == CODER_STATUS_FINISHED_WITH_MARK || XzUnpacker_IsStreamWasFinished(&XZ->state))
        return XZ_STREAM_END;
    if (XZ->status == CODER_STATUS_NOT_FINISHED && XZ->avail_out == 0)
        return XZ_RESULT_OK;
    if (((inbytes == 0) && (outbytes == 0)) || res != SZ_OK) {
        if (res == SZ_ERROR_MEM) {
            return XZ_DIC_HEURISTIC;
        }
	return XZ_RESULT_DATA_ERROR;
    }
    return XZ_RESULT_OK;
}
