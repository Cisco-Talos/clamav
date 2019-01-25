/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2011-2013 Sourcefire, Inc.
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

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/stat.h>
#ifdef	HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <time.h>

#include "jpeg.h"
#include "clamav.h"

#define EC16(x) le16_to_host(x)

#define GETBYTE(v)                                              \
    if(fmap_readn(map, &v, offset, sizeof(v)) == sizeof(v)) {   \
	offset += sizeof(v);					\
    } else {							\
	cli_errmsg("cli_parse(jpeg|gif): Can't read file (corrupted?)\n");	\
	return CL_EPARSE;					\
    }

int cli_parsejpeg(cli_ctx *ctx)
{
	fmap_t *map = *ctx->fmap;
	unsigned char marker, prev_marker, prev_segment = 0, v1, v2, buff[8];
	unsigned int offset = 0, i, len, comment = 0, segment = 0, app = 0;

    cli_dbgmsg("in cli_parsejpeg()\n");

    if(fmap_readn(map, buff, offset, 4) != 4)
	return CL_SUCCESS; /* Ignore */

    if(!memcmp(buff, "\xff\xd8\xff", 3))
	offset = 2;
    else if(!memcmp(buff, "\xff\xd9\xff\xd8", 4))
	offset = 4;
    else
	return CL_SUCCESS; /* Not a JPEG file */

    while(1) {
	segment++;
	prev_marker = 0;
	for(i = 0; offset < map->len && i < 16; i++) {
	    GETBYTE(marker);
	    if(prev_marker == 0xff && marker != 0xff)
		break;
	    prev_marker = marker;
	}
	if(i == 16) {
	    cli_warnmsg("cli_parsejpeg: Spurious bytes before segment %u\n", segment);
	    return CL_EPARSE;
	}
	if(offset == map->len) {
	    cli_warnmsg("cli_parsejpeg: Error looking for marker\n");
	    return CL_EPARSE;
	}
	GETBYTE(v1);
	GETBYTE(v2);
	len = (unsigned int) (v1 << 8) | v2;
	cli_dbgmsg("JPEG: Marker %02x, length %u\n", marker, len);
	if(len < 2) {
	    cli_warnmsg("cli_parsejpeg: Invalid segment size\n");
	    return CL_EPARSE;
	}
	if(len >= map->len - offset + 2) {
	    cli_warnmsg("cli_parsejpeg: Segment data out of file\n");
	    return CL_EPARSE;
	}
	offset += len - 2;

        switch(marker) {
            case 0xe0: /* JFIF */
		if(app) {
		    cli_warnmsg("cli_parsejpeg: Duplicate Application Marker\n");
		    return CL_EPARSE;
		}
		if(segment != 1 && (segment != 2 || !comment)) {
		    cli_warnmsg("cli_parsejpeg: JFIF marker at wrong position\n");
		    return CL_EPARSE;
		}
		if(fmap_readn(map, buff, offset - len + 2, 5) != 5 || memcmp(buff, "JFIF\0",5)) {
		    cli_warnmsg("cli_parsejpeg: No JFIF marker\n");
		    return CL_EPARSE;
                }
                if(len < 16) {
		    cli_warnmsg("cli_parsejpeg: JFIF header too short\n");
		    return CL_EPARSE;
                }
		app = 0xe0;
                break;

            case 0xe1: /* EXIF */
		if(fmap_readn(map, buff, offset - len + 2, 7) != 7) {
		    cli_warnmsg("cli_parsejpeg: Can't read Exif header\n");
		    return CL_EPARSE;
		}
		if(!memcmp(buff, "Exif\0\0", 6)) {
		    if(app && app != 0xe0) {
			cli_warnmsg("cli_parsejpeg: Duplicate Application Marker\n");
			return CL_EPARSE;
		    }
		    if(segment > 3 && !comment && app != 0xe0) {
			cli_warnmsg("cli_parsejpeg: Exif marker at wrong position\n");
			return CL_EPARSE;
		    }
		} else if(!memcmp(buff, "http://", 7)) {
		    cli_dbgmsg("JPEG: XMP data in segment %u\n", segment);
                } else {
		    cli_warnmsg("cli_parsejpeg: Invalid Exif header\n");
		    return CL_EPARSE;
		}
                if(len < 16) {
		    cli_warnmsg("cli_parsejpeg: Exif header too short\n");
		    return CL_EPARSE;
                }
		app = 0xe1;
                break;

            case 0xe8: /* SPIFF */
		if(app) {
		    cli_warnmsg("cli_parsejpeg: Duplicate Application Marker\n");
		    return CL_EPARSE;
		}
		if(segment != 1 && (segment != 2 || !comment)) {
		    cli_warnmsg("cli_parsejpeg: SPIFF marker at wrong position\n");
		    return CL_EPARSE;
		}
		if(fmap_readn(map, buff, offset - len + 2, 6) != 6 || memcmp(buff, "SPIFF\0", 6)) {
		    cli_warnmsg("cli_parsejpeg: No SPIFF marker\n");
		    return CL_EPARSE;
                }
                if(len < 16) {
		    cli_warnmsg("cli_parsejpeg: SPIFF header too short\n");
		    return CL_EPARSE;
                }
		app = 0xe8;
                break;

	    case 0xf7: /* JPG7 */
		if(app) {
		    cli_warnmsg("cli_parsejpeg: Application Marker before JPG7\n");
		    return CL_EPARSE;
                }
		return CL_SUCCESS;

	    case 0xda: /* SOS */
		if(!app) {
		    cli_warnmsg("cli_parsejpeg: Invalid file structure\n");
		    return CL_EPARSE;
                }
		return CL_SUCCESS;

            case 0xd9: /* EOI */
                cli_warnmsg("cli_parsejpeg: No image in jpeg\n");
                return CL_EPARSE;

            case 0xfe: /* COM */
		comment = 1;
                break;

            case 0xed: /* IPTC */
		comment = 1;
                break;

	    case 0xf2: /* DTT */
		if(prev_segment != 0xf1) {
		    cli_warnmsg("cli_parsejpeg: No DTI segment before DTT\n");
		    return CL_EPARSE;
		}
		break;

            default:
                break;
        }
	prev_segment = marker;
    }
    return CL_SUCCESS;
}

/* GIF */

struct gif_screen_desc {
    uint16_t width;
    uint16_t height;
    uint8_t flags;
    uint8_t bgcolor;
    uint8_t aspect;
};

struct gif_graphic_control_ext {
    uint8_t blksize;
    uint8_t flags;
    uint16_t delaytime;
    uint8_t tcoloridx;
    uint8_t blkterm;
};

struct gif_image_desc {
    uint16_t leftpos;
    uint16_t toppos;
    uint16_t width;
    uint16_t height;
    uint8_t flags;
};

int cli_parsegif(cli_ctx *ctx)
{
	fmap_t *map = *ctx->fmap;
	unsigned char magic[6], v;
	unsigned int offset = 0, have_gce = 0;
	struct gif_screen_desc screen_desc;
	struct gif_graphic_control_ext graphic_control_ext;
	struct gif_image_desc image_desc;

    cli_dbgmsg("in cli_parsegif()\n");

    if(fmap_readn(map, magic, offset, 6) != 6)
	return CL_SUCCESS; /* Ignore */

    if(!memcmp(magic, "GIF87a", 6) || !memcmp(magic, "GIF89a", 6))
	offset = 6;
    else
	return CL_SUCCESS; /* Not a GIF file */

    if(fmap_readn(map, &screen_desc, offset, sizeof(screen_desc)) != sizeof(screen_desc)) {
	cli_warnmsg("cli_parsegif: Can't read Logical Screen Descriptor block\n");
	return CL_EPARSE;
    }
    offset += 7;

    cli_dbgmsg("GIF: Screen size %ux%u, gctsize: %u\n", EC16(screen_desc.width), EC16(screen_desc.height), screen_desc.flags & 0x7);
    if(screen_desc.flags & 0x80)
	offset += 3 * (1 << ((screen_desc.flags & 0x7) + 1));

    while(1) {
	GETBYTE(v);
	if(v == 0x21) {
	    GETBYTE(v);
	    if(v == 0xf9) {
		if(fmap_readn(map, &graphic_control_ext, offset, sizeof(graphic_control_ext)) != sizeof(graphic_control_ext)) {
		    cli_warnmsg("cli_parsegif: Can't read Graphic Control Extension block\n");
		    return CL_EPARSE;
		}
		if(have_gce) {
		    cli_warnmsg("cli_parsegif: Multiple Graphic Control Extension blocks not allowed\n");
		    return CL_EPARSE;
		}
		have_gce = 1;
		offset += sizeof(graphic_control_ext);
		if(graphic_control_ext.blksize != 4 || graphic_control_ext.blkterm) {
		    cli_warnmsg("cli_parsegif: Invalid Graphic Control Extension block\n");
		    return CL_EPARSE;
		}
	    } else {
		while(1) {
		    GETBYTE(v);
		    if(!v)
			break;
		    offset += v;
		}
	    }
	} else if(v == 0x2c) {
	    if(fmap_readn(map, &image_desc, offset, sizeof(image_desc)) != sizeof(image_desc)) {
		cli_warnmsg("cli_parsegif: Can't read Image Descriptor block\n");
		return CL_EPARSE;
	    }
	    offset += 9;
	    cli_dbgmsg("GIF: Image size %ux%u, left pos: %u, top pos: %u\n", EC16(image_desc.width), EC16(image_desc.height), EC16(image_desc.leftpos), EC16(image_desc.toppos));
	    break;
	}
    }

    return CL_SUCCESS;
}
