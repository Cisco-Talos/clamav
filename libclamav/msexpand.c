/*
 *  Copyright (C) 2007-2008 Sourcefire, Inc.
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
#include <stddef.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "clamav.h"
#include "cltypes.h"
#include "others.h"
#include "msexpand.h"

#ifndef HAVE_ATTRIB_PACKED
#define __attribute__(x)
#endif

#ifdef HAVE_PRAGMA_PACK
#pragma pack(1)
#endif

#ifdef HAVE_PRAGMA_PACK_HPPA
#pragma pack 1
#endif

#define EC32(x) le32_to_host(x)
#define EC16(x) le16_to_host(x)

#define MAGIC1	0x44445a53
#define MAGIC2	0x3327f088
#define MAGIC3	0x0041

struct msexp_hdr {
    uint32_t magic1;
    uint32_t magic2;
    uint16_t magic3;
    uint32_t fsize;
} __attribute__((packed));

#ifdef HAVE_PRAGMA_PACK
#pragma pack()
#endif

#ifdef HAVE_PRAGMA_PACK_HPPA
#pragma pack
#endif

#define BSIZE 4096
#define RWBUFF 2048

#define READBYTES				\
    ret = cli_readn(fd, rbuff, RWBUFF);		\
    if(ret == -1)				\
	return CL_EREAD;			\
    if(!ret)					\
	break;					\
    rbytes = (unsigned int) ret;		\
    r = 0;

#define WRITEBYTES				\
    ret = cli_writen(ofd, wbuff, w);		\
    if(ret == -1 || (unsigned int) ret != w)	\
	return CL_EWRITE;			\
    wbytes += w;				\
    if(wbytes >= EC32(hdr.fsize))		\
	return CL_SUCCESS;			\
    w = 0;


int cli_msexpand(int fd, int ofd, cli_ctx *ctx)
{
	struct msexp_hdr hdr;
	uint8_t i, mask, bits;
	unsigned char buff[BSIZE], rbuff[RWBUFF], wbuff[RWBUFF];
	unsigned int j = BSIZE - 16, k, l, r = 0, w = 0, rbytes = 0, wbytes = 0;
	int ret;


    if(cli_readn(fd, &hdr, sizeof(hdr)) == -1)
	return CL_EREAD;

    if(EC32(hdr.magic1) != MAGIC1 || EC32(hdr.magic2) != MAGIC2 || EC16(hdr.magic3) != MAGIC3) {
	cli_dbgmsg("MSEXPAND: Not supported file format\n");
	return CL_EFORMAT;
    }

    cli_dbgmsg("MSEXPAND: File size from header: %u\n", EC32(hdr.fsize));

    if(cli_checklimits("MSEXPAND", ctx, EC32(hdr.fsize), 0, 0)!=CL_CLEAN)
        return CL_SUCCESS;

    while(1) {

	if(!rbytes || (r == rbytes)) {
	    READBYTES;
	}

	bits = rbuff[r]; r++;

	mask = 1;
	for(i = 0; i < 8; i++) {
	    if(bits & mask) {
		if(r == rbytes) {
		    READBYTES;
		}

		if(w == RWBUFF) {
		    WRITEBYTES;
		}

		wbuff[w] = buff[j] = rbuff[r];
		r++; w++;
		j++; j %= BSIZE;
	    } else {
		if(r == rbytes) {
		    READBYTES;
		}
		k = rbuff[r]; r++;

		if(r == rbytes) {
		    READBYTES;
		}
		l = rbuff[r]; r++;

		k += (l & 0xf0) << 4;
		l = (l & 0x0f) + 3;
		while(l--) {
		    if(w == RWBUFF) {
			WRITEBYTES;
		    }
		    wbuff[w] = buff[j] = buff[k];
		    w++;
		    k++; k %= BSIZE;
		    j++; j %= BSIZE;
		}
	    }
	    mask *= 2;
	}
    }

    if(w) {
	WRITEBYTES;
    }

    return CL_SUCCESS;
}
