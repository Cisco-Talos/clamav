/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2011-2013 Sourcefire, Inc.
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
 */

#include <string.h>

#include "clamav.h"
#include "scanners.h"
#include "iso9660.h"
#include "fmap.h"
#include "str.h"
#include "hashtab.h"

typedef struct {
    cli_ctx *ctx;
    size_t base_offset;
    unsigned int blocksz;
    unsigned int sectsz;
    unsigned int fileno;
    unsigned int joliet;
    char buf[260];
    struct cli_hashset dir_blocks;
} iso9660_t;


static const void *needblock(const iso9660_t *iso, unsigned int block, int temp) {
    cli_ctx *ctx = iso->ctx;
    size_t loff;
    unsigned int blocks_per_sect = (2048 / iso->blocksz);
    if(block > (((*ctx->fmap)->len - iso->base_offset) / iso->sectsz) * blocks_per_sect)
	return NULL; /* Block is out of file */
    loff = (block / blocks_per_sect) * iso->sectsz;   /* logical sector */
    loff += (block % blocks_per_sect) * iso->blocksz; /* logical block within the sector */
    if(temp)
	return fmap_need_off_once(*ctx->fmap, iso->base_offset + loff, iso->blocksz);
    return fmap_need_off(*ctx->fmap, iso->base_offset + loff, iso->blocksz);
}


static int iso_scan_file(const iso9660_t *iso, unsigned int block, unsigned int len) {
    char *tmpf;
    int fd, ret = CL_SUCCESS;

    if(cli_gentempfd(iso->ctx->engine->tmpdir, &tmpf, &fd) != CL_SUCCESS)
        return CL_ETMPFILE;

    cli_dbgmsg("iso_scan_file: dumping to %s\n", tmpf);
    while(len) {
        const void *buf = needblock(iso, block, 1);
        unsigned int todo = MIN(len, iso->blocksz);
        if(!buf) {
            /* Block outside file */
            cli_dbgmsg("iso_scan_file: cannot dump block outside file, ISO may be truncated\n");
            ret = CL_EFORMAT;
            break;
        }
        if((unsigned int)cli_writen(fd, buf, todo) != todo) {
            cli_warnmsg("iso_scan_file: Can't write to file %s\n", tmpf);
            ret = CL_EWRITE;
            break;
        }
        len -= todo;
        block++;
    }

    if (!len)
        ret = cli_magic_scandesc(fd, tmpf, iso->ctx);

    close(fd);
    if(!iso->ctx->engine->keeptmp) {
	if(cli_unlink(tmpf)) {
	    ret = CL_EUNLINK;
	}
    }

    free(tmpf);
    return ret;
}

static char *iso_string(iso9660_t *iso, const void *src, unsigned int len) {
    if(iso->joliet) {
	char *utf8;
        const char *uutf8;
	if(len > (sizeof(iso->buf) - 2))
	    len = sizeof(iso->buf) - 2;
	memcpy(iso->buf, src, len);
	iso->buf[len] = '\0';
	iso->buf[len+1] = '\0';
	utf8 = cli_utf16_to_utf8(iso->buf, len, UTF16_BE);
        uutf8 = utf8 ? utf8 : "";
	strncpy(iso->buf, uutf8, sizeof(iso->buf));
	iso->buf[sizeof(iso->buf)-1] = '\0';
	free(utf8);
    } else {
	memcpy(iso->buf, src, len);
	iso->buf[len] = '\0';
    }
    return iso->buf;
}


static int iso_parse_dir(iso9660_t *iso, unsigned int block, unsigned int len) {
    cli_ctx *ctx = iso->ctx;
    int ret = CL_CLEAN;
    int viruses_found = 0;

    if(len < 34) {
	cli_dbgmsg("iso_parse_dir: Directory too small, skipping\n");
	return CL_CLEAN;
    }

    for(; len && ret == CL_CLEAN; block++, len -= MIN(len, iso->blocksz)) {
	const uint8_t *dir, *dir_orig;
	unsigned int dirsz;

	if(iso->dir_blocks.count > 1024) {
	    cli_dbgmsg("iso_parse_dir: Breaking out due to too many dir records\n");
	    return CL_BREAK;
	}

	if(cli_hashset_contains(&iso->dir_blocks, block))
	    continue;

	if((ret = cli_hashset_addkey(&iso->dir_blocks, block)) != CL_CLEAN)
	    return ret;

	dir = dir_orig = needblock(iso, block, 0);
	if(!dir)
	    return CL_CLEAN;

	for(dirsz = MIN(iso->blocksz, len);;) {
	    unsigned int entrysz = *dir, fileoff, filesz;
	    char *sep;

	    if(!dirsz || !entrysz) /* continuing on next block, if any */
		break;
	    if(entrysz > dirsz) { /* record size overlaps onto the next sector, no point in looking in there */
		cli_dbgmsg("iso_parse_dir: Directory entry overflow, breaking out %u %u\n", entrysz, dirsz);
		len = 0;
		break;
	    }
	    if(entrysz < 34) { /* this shouldn't happen really*/
		cli_dbgmsg("iso_parse_dir: Too short directory entry, attempting to skip\n");
		dirsz -= entrysz;
		dir += entrysz;
		continue;
	    }
	    filesz = dir[32];
	    if(filesz == 1 && (dir[33] == 0 || dir[33] == 1)) { /* skip "." and ".." */
		dirsz -= entrysz;
		dir += entrysz;
		continue;
	    }

	    if(filesz + 33 > dirsz) {
		cli_dbgmsg("iso_parse_dir: Directory entry name overflow, clamping\n");
		filesz = dirsz - 33;
	    }
	    iso_string(iso, &dir[33], filesz);
	    sep = memchr(iso->buf, ';', filesz);
	    if(sep)
		*sep = '\0';
	    else
		iso->buf[filesz] = '\0';
	    fileoff = cli_readint32(dir+2);
	    fileoff += dir[1];
	    filesz = cli_readint32(dir+10);

	    cli_dbgmsg("iso_parse_dir: %s '%s': off %x - size %x - flags %x - unit size %x - gap size %x - volume %u\n", (dir[25] & 2) ? "Directory" : "File", iso->buf, fileoff, filesz, dir[25], dir[26], dir[27], cli_readint32(&dir[28]) & 0xffff);
            ret = cli_matchmeta(ctx, iso->buf, filesz, filesz, 0, 0, 0, NULL);
            if (ret == CL_VIRUS) {
                viruses_found = 1;
                if (!SCAN_ALLMATCHES)
                    break;
                ret = CL_CLEAN;
            }

	    if(dir[26] || dir[27])
		cli_dbgmsg("iso_parse_dir: Skipping interleaved file\n");
	    else  {
		/* TODO Handle multi-extent ? */
		if(dir[25] & 2) {
		    ret = iso_parse_dir(iso, fileoff, filesz);
		} else {
		    if(cli_checklimits("ISO9660", ctx, filesz, 0, 0) != CL_SUCCESS)
			cli_dbgmsg("iso_parse_dir: Skipping overlimit file\n");
		    else
			ret = iso_scan_file(iso, fileoff, filesz);
		}
                if (ret == CL_VIRUS) {
                    viruses_found = 1;
                    if (!SCAN_ALLMATCHES)
                        break;
                    ret = CL_CLEAN;
                }
	    }
	    dirsz -= entrysz;
	    dir += entrysz;
	}

	fmap_unneed_ptr(*ctx->fmap, dir_orig, iso->blocksz);
    }
    if (viruses_found == 1)
        return CL_VIRUS;
    return ret;
}

int cli_scaniso(cli_ctx *ctx, size_t offset) {
    const uint8_t *privol, *next;
    iso9660_t iso;
    int i;

    if(offset < 32768)
	return CL_CLEAN; /* Need 16 sectors at least 2048 bytes long */

    privol = fmap_need_off(*ctx->fmap, offset, 2448 + 6);
    if(!privol)
	return CL_CLEAN;

    next = (uint8_t *)cli_memstr((char *)privol + 2049, 2448 + 6 - 2049, "CD001", 5);
    if(!next)
	return CL_CLEAN; /* Find next volume descriptor */

    iso.sectsz = (next - privol) - 1;
    if(iso.sectsz * 16 > offset)
	return CL_CLEAN; /* Need room for 16 system sectors */

    iso.blocksz = cli_readint32(privol+128) & 0xffff;
    if(iso.blocksz != 512 && iso.blocksz != 1024 && iso.blocksz != 2048)
	return CL_CLEAN; /* Likely not a cdrom image */

    iso.base_offset = offset - iso.sectsz * 16;
    iso.joliet = 0;

    for(i=16; i<32 ;i++) { /* scan for a joliet secondary volume descriptor */
	next = fmap_need_off_once(*ctx->fmap, iso.base_offset + i * iso.sectsz, 2048);
	if(!next)
	    break; /* Out of disk */
	if(*next == 0xff || memcmp(next+1, "CD001", 5))
	    break; /* Not a volume descriptor */
	if(*next != 2)
	    continue; /* Not a secondary volume descriptor */
	if(next[88] != 0x25 || next[89] != 0x2f)
	    continue; /* Not a joliet descriptor */
	if(next[156+26] || next[156+27])
	    continue; /* Root is interleaved so we fallback to the primary descriptor */
	switch(next[90]) {
	case 0x40: /* Level 1 */
	    iso.joliet = 1;
	    break;
	case 0x43: /* Level 2 */
	    iso.joliet = 2;
	    break;
	case 0x45: /* Level 3 */
	    iso.joliet = 3;
	    break;
	default: /* Not Joliet */
	    continue;
	}
	break;
    }

    /* TODO rr, el torito, udf ? */

    /* NOTE: freeing sector now. it is still safe to access as we don't alloc anymore */
    fmap_unneed_off(*ctx->fmap, offset, 2448);
    if(iso.joliet)
	privol = next;

    cli_dbgmsg("in cli_scaniso\n");
    if(cli_debug_flag) {
	cli_dbgmsg("cli_scaniso: Raw sector size: %u\n", iso.sectsz);
	cli_dbgmsg("cli_scaniso: Block size: %u\n", iso.blocksz);

	cli_dbgmsg("cli_scaniso: Volume descriptor version: %u\n", privol[6]);

#define ISOSTRING(src, len) iso_string(&iso, (src), (len))
	cli_dbgmsg("cli_scaniso: System: %s\n", ISOSTRING(privol + 8, 32));
	cli_dbgmsg("cli_scaniso: Volume: %s\n", ISOSTRING(privol + 40, 32));

	cli_dbgmsg("cli_scaniso: Volume space size: 0x%x blocks\n", cli_readint32(&privol[80]));
	cli_dbgmsg("cli_scaniso: Volume %u of %u\n", cli_readint32(privol+124) & 0xffff, cli_readint32(privol+120) & 0xffff);

	cli_dbgmsg("cli_scaniso: Volume Set: %s\n", ISOSTRING(privol + 190, 128));
	cli_dbgmsg("cli_scaniso: Publisher: %s\n", ISOSTRING(privol + 318, 128));
	cli_dbgmsg("cli_scaniso: Data Preparer: %s\n", ISOSTRING(privol + 446, 128));
	cli_dbgmsg("cli_scaniso: Application: %s\n", ISOSTRING(privol + 574, 128));

#define ISOTIME(s,n) cli_dbgmsg("cli_scaniso: "s": %c%c%c%c-%c%c-%c%c %c%c:%c%c:%c%c\n", privol[n],privol[n+1],privol[n+2],privol[n+3], privol[n+4],privol[n+5], privol[n+6],privol[n+7], privol[n+8],privol[n+9], privol[n+10],privol[n+11], privol[n+12],privol[n+13])
	ISOTIME("Volume creation time",813);
	ISOTIME("Volume modification time",830);
	ISOTIME("Volume expiration time",847);
	ISOTIME("Volume effective time",864);

	cli_dbgmsg("cli_scaniso: Path table size: 0x%x\n", cli_readint32(privol+132) & 0xffff);
	cli_dbgmsg("cli_scaniso: LSB Path Table: 0x%x\n", cli_readint32(privol+140));
	cli_dbgmsg("cli_scaniso: Opt LSB Path Table: 0x%x\n", cli_readint32(privol+144));
	cli_dbgmsg("cli_scaniso: MSB Path Table: 0x%x\n", cbswap32(cli_readint32(privol+148)));
	cli_dbgmsg("cli_scaniso: Opt MSB Path Table: 0x%x\n", cbswap32(cli_readint32(privol+152)));
	cli_dbgmsg("cli_scaniso: File Structure Version: %u\n", privol[881]);

	if(iso.joliet)
	    cli_dbgmsg("cli_scaniso: Joliet level %u\n", iso.joliet);
    }

    if(privol[156+26] || privol[156+27]) {
	cli_dbgmsg("cli_scaniso: Interleaved root directory is not supported\n");
	return CL_CLEAN;
    }

    iso.ctx = ctx;
    i = cli_hashset_init(&iso.dir_blocks, 1024, 80);
    if(i != CL_SUCCESS)
	return i;
    i = iso_parse_dir(&iso, cli_readint32(privol+156+2) + privol[156+1], cli_readint32(privol+156+10));
    cli_hashset_destroy(&iso.dir_blocks);
    if(i == CL_BREAK)
	return CL_CLEAN;
    return i;
}

