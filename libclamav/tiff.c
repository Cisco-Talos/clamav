/*
 *  Copyright (C) 2015-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 *  Authors: Kevin Lin <kevlin2@cisco.com>
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

#include "others.h"
#include "tiff.h"

#define tiff32_to_host(be,x) (be ? be32_to_host(x) : le32_to_host(x))
#define tiff16_to_host(be,x) (be ? be16_to_host(x) : le16_to_host(x))

struct tiff_ifd {
    uint16_t tag;
    uint16_t type;
    uint32_t numval;
    uint32_t value;
};

int cli_parsetiff(cli_ctx *ctx)
{
	fmap_t *map = *ctx->fmap;
    unsigned char magic[4];
    int big_endian;
    uint32_t offset = 0, ifd_count = 0;
    uint16_t i, num_entries;
    struct tiff_ifd entry;
    size_t value_size;

    cli_dbgmsg("in cli_parsetiff()\n");

    /* check the magic */
    if(fmap_readn(map, magic, offset, 4) != 4)
        return CL_SUCCESS;
    offset += 4;

    if(!memcmp(magic, "\x4d\x4d\x00\x2a", 4))
        big_endian = 1;
    else if(!memcmp(magic, "\x49\x49\x2a\x00", 4))
        big_endian = 0;
    else
        return CL_SUCCESS; /* Not a TIFF file */

    cli_dbgmsg("cli_parsetiff: %s-endian tiff file\n", big_endian ? "big" : "little");

    /* acquire offset of first IFD */
    if(fmap_readn(map, &offset, offset, 4) != 4)
        return CL_EPARSE;
    offset = tiff32_to_host(big_endian, offset);

    cli_dbgmsg("cli_parsetiff: first IFD located @ offset %u\n", offset);

    if(!offset) {
        cli_errmsg("cli_parsetiff: invalid offset for first IFD\n");
        return CL_EPARSE;
    }

    /* each IFD represents a subfile, though only the first one normally matters */
    do {
        /* acquire number of directory entries in current IFD */
        if(fmap_readn(map, &num_entries, offset, 2) != 2)
            return CL_EPARSE;
        offset += 2;
        num_entries = tiff16_to_host(big_endian, num_entries);

        cli_dbgmsg("cli_parsetiff: IFD %u declared %u directory entries\n", ifd_count, num_entries);

        /* transverse IFD entries */
        for(i = 0; i < num_entries; i++) {
            if(fmap_readn(map, &entry, offset, sizeof(entry)) != sizeof(entry))
                return CL_EPARSE;
            offset += sizeof(entry);

            entry.tag = tiff16_to_host(big_endian, entry.tag);
            entry.type = tiff16_to_host(big_endian, entry.type);
            entry.numval = tiff32_to_host(big_endian, entry.numval);
            entry.value = tiff32_to_host(big_endian, entry.value);

            //cli_dbgmsg("%02u: %u %u %u %u\n", i, entry.tag, entry.type, entry.numval, entry.value);

            value_size = entry.numval;
            switch(entry.type) {
            case 1: /* BYTE */
                value_size *= 1;
                break;
            case 2: /* ASCII */
                value_size *= 1;
                break;
            case 3: /* SHORT */
                value_size *= 2;
                break;
            case 4: /* LONG */
                value_size *= 4;
                break;
            case 5: /* RATIONAL (LONG/LONG) */
                value_size *= 8;
                break;

                /* TIFF 6.0 Types */
            case 6: /* SBYTE */
                value_size *= 1;
                break;
            case 7: /* UNDEFINED */
                value_size *= 1;
                break;
            case 8: /* SSHORT */
                value_size *= 2;
                break;
            case 9: /* SLONG */
                value_size *= 4;
                break;
            case 10: /* SRATIONAL (SLONG/SLONG) */
                value_size *= 8;
                break;
            case 11: /* FLOAT */
                value_size *= 4;
                break;
            case 12: /* DOUBLE */
                value_size *= 8;
                break;

            default: /* INVALID or NEW Type */
                value_size *= 0;
                break;
            }

            if(value_size > sizeof(entry.value)) {
                if(entry.value + value_size > map->len) {
                    cli_warnmsg("cli_parsetiff: TFD entry field %u exceeds bounds of TIFF file [%llu > %llu]\n",
                                i, (long long unsigned)(entry.value + value_size), (long long unsigned)map->len);
                    return cli_append_virus(ctx, "Heuristics.TIFF.OutOfBoundsAccess");
                }
            }
        }

        ifd_count++;

        /* acquire next IFD location, gets 0 if last IFD */
        if(fmap_readn(map, &offset, offset, sizeof(offset)) != sizeof(offset))
            return CL_EPARSE;
        offset = tiff32_to_host(big_endian, offset);
    } while(offset);

    cli_dbgmsg("cli_parsetiff: examined %u IFD(s)\n", ifd_count);

    return CL_SUCCESS;
}
