/*
*  Copyright (C) 2015 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
*  Copyright (C) 2011 Sourcefire, Inc.
*
*  Authors: Tomasz Kojm <tkojm@clamav.net>
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

#include "gif.h"
#include "scanners.h"
#include "clamav.h"

#ifndef HAVE_ATTRIB_PACKED
#define __attribute__(x)
#endif
#ifdef HAVE_PRAGMA_PACK
#pragma pack(1)
#endif
#ifdef HAVE_PRAGMA_PACK_HPPA
#pragma pack 1
#endif

struct gif_screen_desc {
    uint16_t width;
    uint16_t height;
    uint8_t flags;
    uint8_t bgcolor;
    uint8_t aspect;
} __attribute__((packed));

struct gif_graphic_control_ext {
    uint8_t blksize;
    uint8_t flags;
    uint16_t delaytime;
    uint8_t tcoloridx;
    uint8_t blkterm;
} __attribute__((packed));

struct gif_image_desc {
    uint16_t leftpos;
    uint16_t toppos;
    uint16_t width;
    uint16_t height;
    uint8_t flags;
} __attribute__((packed));

#ifdef HAVE_PRAGMA_PACK
#pragma pack()
#endif
#ifdef HAVE_PRAGMA_PACK_HPPA
#pragma pack
#endif

#define EC16(x) le16_to_host(x)

#define GETDATA(v)                                                  \
    {                                                               \
    if(fmap_readn(map, &v, offset, sizeof(v)) == sizeof(v)) {       \
	    offset += sizeof(v);                                        \
    } else {                                                        \
	    cli_errmsg("cli_parsegif: Can't read file (truncated?)\n"); \
	    return CL_EPARSE;                                           \
    }                                                               \
    }

int cli_parsegif(cli_ctx *ctx)
{
    fmap_t *map = *ctx->fmap;
    unsigned char v = 0;
    unsigned int offset = 6;
    struct gif_screen_desc screen_desc;
    struct gif_image_desc image_desc;
    int retVal = CL_SUCCESS;

    cli_dbgmsg("in cli_parsegif()\n");

    GETDATA(screen_desc);
    cli_dbgmsg("GIF: Screen size %ux%u, gctsize: %u\n", EC16(screen_desc.width), EC16(screen_desc.height), screen_desc.flags & 0x7);
    if (screen_desc.flags & 0x80)
        offset += 3 * (1 << ((screen_desc.flags & 0x7) + 1));

    while (1) {
        GETDATA(v);
        if (v == 0x21) {
            GETDATA(v);
            if (v == 0xf9) {
                offset += sizeof(struct gif_graphic_control_ext);
            }
            else {
                while (1) {
                    GETDATA(v);
                    if (!v)
                        break;

                    if (offset + v > map->len)
                    {
                        retVal = CL_EPARSE;
                        goto scan_overlay;
                    }
                    offset += v;
                }
            }
        }
        else if (v == 0x2c) {
            GETDATA(image_desc);
            cli_dbgmsg("GIF: Image size %ux%u, left pos: %u, top pos: %u\n", EC16(image_desc.width), EC16(image_desc.height), EC16(image_desc.leftpos), EC16(image_desc.toppos));

            offset++;
            if (image_desc.flags & 0x80)
                offset += 3 * (1 << ((image_desc.flags & 0x7) + 1));

            while (1) {
                GETDATA(v);
                if (!v)
                    break;

                if (offset + v > map->len)
                {
                    retVal = CL_EPARSE;
                    goto scan_overlay;
                }
                offset += v;
            }
        }
        else if (v == 0x3b) {
            break;
        }
        else {
            // An unknown code: break.
            retVal = CL_EPARSE;
            goto scan_overlay;
        }
    }

scan_overlay:
    // Some recovery (I saw some "GIF89a;" or things like this)
    if (retVal == CL_EPARSE &&
        offset == (6 + sizeof(screen_desc) + 1))
        offset = 6;

    // Is there an overlay?
    if (offset < map->len)
    {
        int recRetVal = cli_map_scan(map, offset, map->len - offset, ctx, CL_TYPE_ANY);
        retVal = recRetVal != CL_SUCCESS ? recRetVal : retVal;
    }

    return retVal;
}