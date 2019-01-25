/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2010-2013 Sourcefire, Inc.
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
 *
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <string.h>

#include "scanners.h"
#include "others.h"
#include "clamav.h"
#include "fmap.h"
#include "binhex.h"


static const uint8_t hqxtbl[] = {
    /*           00   01   02   03   04   05   06   07   08   09   0a   0b   0c   0d   0e   0f */
    /* 00-0f */	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    /* 10-1f */	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    /* 20-2f */	0xff,0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0xff,0xff,
    /* 30-3f */	0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,0xff,0x14,0x15,0xff,0xff,0xff,0xff,0xff,0xff,
    /* 40-4f */	0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x20,0x21,0x22,0x23,0x24,0xff,
    /* 50-5f */	0x25,0x26,0x27,0x28,0x29,0x2a,0x2b,0xff,0x2c,0x2d,0x2e,0x2f,0xff,0xff,0xff,0xff,
    /* 60-6f */	0x30,0x31,0x32,0x33,0x34,0x35,0x36,0xff,0x37,0x38,0x39,0x3a,0x3b,0x3c,0xff,0xff,
    /* 70-7f */	0x3d,0x3e,0x3f,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
};

#define BH_FLUSH_SZ (BUFSIZ - 256)

int cli_binhex(cli_ctx *ctx) {
    fmap_t *map = *ctx->fmap;
    const uint8_t *encoded = NULL;
    uint8_t decoded[BUFSIZ], spare_bits = 0, last_byte = 0, this_byte = 0, offset = 0;
    size_t enc_done=0, enc_todo=map->len;
    unsigned int dec_done=0, chunksz = 0, chunkoff=0;
    uint32_t datalen = 0, reslen = 0;
    int in_data = 0, in_run = 0, datafd, resfd, ret = CL_CLEAN;
    enum binhex_phase { IN_BANNER, IN_HEADER, IN_DATA, IN_LIMBO1, IN_LIMBO2, IN_RES } write_phase = IN_BANNER;
    char *dname, *rname;

    cli_dbgmsg("in cli_binhex\n");
    if(!map->len) return CL_CLEAN;

    if((ret = cli_gentempfd(ctx->engine->tmpdir, &dname, &datafd)) != CL_SUCCESS)
	return ret;

    if((ret = cli_gentempfd(ctx->engine->tmpdir, &rname, &resfd)) != CL_SUCCESS) {
	close(datafd);
	if(cli_unlink(dname)) ret = CL_EUNLINK;
	free(dname);
	return ret;
    }

    memset(decoded, 0, 24);

    while(1) {
	uint8_t b;
	if(!enc_todo || dec_done >= BH_FLUSH_SZ) {
	    if(write_phase == IN_HEADER) {
		uint32_t namelen = (uint32_t)decoded[0], hdrlen = 1 + namelen + 1 + 4 + 4 + 2;
		if(!dec_done) {
		    cli_dbgmsg("cli_binhex: file is empty\n");
		    break;
		}
		datalen = (decoded[hdrlen]<<24) | (decoded[hdrlen+1]<<16) | (decoded[hdrlen+2]<<8) | decoded[hdrlen+3];
		hdrlen += 4;
		reslen = (decoded[hdrlen]<<24) | (decoded[hdrlen+1]<<16) | (decoded[hdrlen+2]<<8) | decoded[hdrlen+3];
		hdrlen += 4 + 2;
		decoded[namelen+1] = 0;
		if(dec_done <= hdrlen) {
		    cli_dbgmsg("cli_binhex: file too short for header\n");
		    break;
		}
		if((ret = cli_checklimits("cli_binhex(data)", ctx, datalen, 0, 0)) != CL_CLEAN)
		    break;
		if(cli_checklimits("cli_binhex(resources)", ctx, reslen, 0, 0) != CL_CLEAN)
		    reslen = 0;
		cli_dbgmsg("cli_binhex: decoding '%s' - %u bytes of data to %s - %u bytes or resources to %s\n", decoded+1, datalen, dname, reslen, rname);
		memmove(decoded, &decoded[hdrlen], dec_done - hdrlen);
		dec_done -= hdrlen;
		write_phase++;
	    }
	    if(dec_done && write_phase == IN_DATA) {
		unsigned int todo = MIN(dec_done, datalen);
		datalen -= todo;
		dec_done -= todo;
		if(cli_writen(datafd, decoded, todo)!=(int)todo) {
		    ret = CL_EWRITE;
		    break;
		}
		if(!datalen) {
		    write_phase++;
		    if (lseek(datafd, 0, SEEK_SET) == -1) {
                cli_dbgmsg("cli_binhex: call to lseek() has failed\n");
                ret = CL_ESEEK;
                break;
            }
		    ret = cli_magic_scandesc(datafd, dname, ctx);
		    if(ret == CL_VIRUS) break;
		}
		if(dec_done)
		    memmove(decoded, &decoded[todo], dec_done);
	    }
	    if(dec_done && write_phase == IN_LIMBO1) {
		if(dec_done > 1) {
		    if(reslen<5) {
			cli_dbgmsg("cli_binhex: skipping resources (too small)\n");
			break;
		    }
		    dec_done-=2;
		    write_phase+=2;
		    if(dec_done)
			memmove(decoded, &decoded[2], dec_done);
		} else {
		    dec_done--;
		    write_phase++;
		    if(dec_done)
			memmove(decoded, &decoded[1], dec_done);
		}
	    }
	    if(dec_done && write_phase == IN_LIMBO2) {
		if(reslen<5) {
		    cli_dbgmsg("cli_binhex: skipping resources (too small)\n");
		    break;
		}
		write_phase++;
		if(--dec_done)
		    memmove(decoded, &decoded[1], dec_done);
	    }
	    if(dec_done && write_phase == IN_RES) {
		unsigned int todo = MIN(dec_done, reslen);
		reslen -= todo;
		dec_done -= todo;
		if(cli_writen(resfd, decoded, todo)!=(int)todo) {
		    ret = CL_EWRITE;
		    break;
		}
		if(!reslen) {
		    if (lseek(resfd, 0, SEEK_SET) == -1) {
                cli_dbgmsg("cli_binhex: call to lseek() has failed\n");
                ret = CL_ESEEK;
                break;
            }
		    ret = cli_magic_scandesc(resfd, rname, ctx);
		    break;
		}
	    }
	    if(!enc_todo) {
		if(write_phase == IN_DATA) {
		    cli_dbgmsg("cli_binhex: scanning partially extracted data fork\n");
		    if (lseek(datafd, 0, SEEK_SET) == -1) {
                cli_dbgmsg("cli_binhex: call to lseek() has failed\n");
                ret = CL_ESEEK;
                break;
            }
		    ret = cli_magic_scandesc(datafd, dname, ctx);
		} else if(write_phase == IN_RES) {
		    cli_dbgmsg("cli_binhex: scanning partially extracted resource fork\n");
		    if (lseek(resfd, 0, SEEK_SET) == -1) {
                cli_dbgmsg("cli_binhex: call to lseek() has failed\n");
                ret = CL_ESEEK;
                break;
            }
		    ret = cli_magic_scandesc(resfd, rname, ctx);
		}
		break;
	    }
	}

	// 'chunksz' must be 0 the first iteration, 
	// so that 'encoded' will be initialized before first dereference.
	if(!chunksz)
	{
	    chunksz = MIN(enc_todo, map->pgsz);
	    encoded = fmap_need_off_once(map, enc_done, chunksz);
	    if(!encoded) {
		ret = CL_EREAD;
		break;
	    }
	    chunkoff = 0;
	}
	chunksz--;

	b = encoded[chunkoff++];
	enc_done++;
	enc_todo--;

	if((char)b == '\r' || (char)b == '\n') {
	    in_data = 1;
	    continue;
	}
	if(!in_data) continue;
	if(write_phase == IN_BANNER) {
	    if((char)b != ':') {
		cli_dbgmsg("cli_binhex: broken file (missing stream start identifier)\n");
		break;
	    }
	    write_phase++;
	}
	if((char)b == ':')
	    continue;
	if(b > 0x7f || (b = hqxtbl[b]) == 0xff) {
	    cli_dbgmsg("cli_binhex: Invalid character (%02x)\n", encoded[chunkoff-1]);
	    break;
	}
	switch((offset++) & 3) { /* 6 bits per char */
	case 0: /* left-6h */
	    spare_bits = b<<2;
	    continue;
	case 1: /* left-2l + middle-4h */
	    this_byte = spare_bits | (b>>4);
	    spare_bits = b<<4;
	    break;
	case 2: /* middle-4l + right-2h */
	    this_byte = spare_bits | (b>>2);
	    spare_bits = b<<6;
	    break;
	case 3: /* right-6l */
	    this_byte = spare_bits | b;
	}

	if(in_run) {
	    in_run = 0;
	    if(!this_byte)
		this_byte = 0x90;
	    else {
		while(--this_byte) 
		    decoded[dec_done++] = last_byte;
		continue;
	    }
	} else if(this_byte == 0x90) {
	    in_run = 1;
	    continue;
	}
	decoded[dec_done++] = this_byte;
	last_byte = this_byte;
    }

    close(datafd);
    close(resfd);
    if(!ctx->engine->keeptmp) {
	if(cli_unlink(dname) && ret != CL_VIRUS) ret = CL_EUNLINK;
	if(cli_unlink(rname) && ret != CL_VIRUS) ret = CL_EUNLINK;
    }
    free(dname);
    free(rname);
    return ret;
}
