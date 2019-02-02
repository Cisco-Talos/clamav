/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2009-2013 Sourcefire, Inc.
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
#include <ctype.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "clamav.h"
#include "others.h"
#include "cpio.h"
#include "scanners.h"
#include "matcher.h"

struct cpio_hdr_old {
    uint16_t magic;
    uint16_t dev;
    uint16_t ino;
    uint16_t mode;
    uint16_t uid;
    uint16_t gid;
    uint16_t nlink;
    uint16_t rdev;
    uint16_t mtime[2];
    uint16_t namesize;
    uint16_t filesize[2];
};

struct cpio_hdr_odc {
    char magic[6];
    char dev[6];
    char ino[6];
    char mode[6];
    char uid[6];
    char gid[6];
    char nlink[6];
    char rdev[6];
    char mtime[11];
    char namesize[6];
    char filesize[11];
};

struct cpio_hdr_newc {
    char magic[6];
    char ino[8];
    char mode[8];
    char uid[8];
    char gid[8];
    char nlink[8];
    char mtime[8];
    char filesize[8];
    char devmajor[8];
    char devminor[8];
    char rdevmajor[8];
    char rdevminor[8];
    char namesize[8];
    char check[8];
};

#define EC16(v, conv)   (conv ? cbswap16(v) : v)

static void sanitname(char *name)
{
    while(*name) {
	if(!isascii(*name) || strchr("%\\\t\n\r", *name))
	    *name = '_';
	name++;
    }
}

int cli_scancpio_old(cli_ctx *ctx)
{
	struct cpio_hdr_old hdr_old;
	char name[513];
	unsigned int file = 0, trailer = 0;
	uint32_t filesize, namesize, hdr_namesize;
	int ret = CL_CLEAN, conv;
	off_t pos = 0;
        int virus_found = 0;


    while(fmap_readn(*ctx->fmap, &hdr_old, pos, sizeof(hdr_old)) == sizeof(hdr_old)) {
	pos += sizeof(hdr_old);
	if(!hdr_old.magic && trailer) {
            ret = CL_SUCCESS;
	    goto leave;
        }

	if(hdr_old.magic == 070707) {
	    conv = 0;
	} else if(hdr_old.magic == 0143561) {
	    conv = 1;
	} else {
	    cli_dbgmsg("cli_scancpio_old: Invalid magic number\n");
	    ret = CL_EFORMAT;
            goto leave;
	}

	cli_dbgmsg("CPIO: -- File %u --\n", ++file);

	if(hdr_old.namesize) {
	    hdr_namesize = EC16(hdr_old.namesize, conv);
	    namesize = MIN(sizeof(name), hdr_namesize);
	    if ((uint32_t)fmap_readn(*ctx->fmap, &name, pos, namesize) != namesize) {
		cli_dbgmsg("cli_scancpio_old: Can't read file name\n");
		return CL_EFORMAT;
	    }
	    pos += namesize;
	    name[namesize - 1] = 0;
	    sanitname(name);
	    cli_dbgmsg("CPIO: Name: %s\n", name);
	    if(!strcmp(name, "TRAILER!!!"))
		trailer = 1;

	    if(namesize < hdr_namesize) {
		if(hdr_namesize % 2)
		    hdr_namesize++;
		pos += hdr_namesize - namesize;
	    } else if(hdr_namesize % 2)
		pos++;
	}
        filesize = (uint32_t)((uint32_t)EC16(hdr_old.filesize[0], conv) << 16 | EC16(hdr_old.filesize[1], conv));
	cli_dbgmsg("CPIO: Filesize: %u\n", filesize);
	if(!filesize)
	    continue;

	if(cli_matchmeta(ctx, name, filesize, filesize, 0, file, 0, NULL) == CL_VIRUS) {
            if (!SCAN_ALLMATCHES)
                return CL_VIRUS;
            virus_found = 1;
        }


	if((EC16(hdr_old.mode, conv) & 0170000) != 0100000) {
	    cli_dbgmsg("CPIO: Not a regular file, skipping\n");
	} else {
	    ret = cli_checklimits("cli_scancpio_old", ctx, filesize, 0, 0);
	    if(ret == CL_EMAXFILES) {
		goto leave;
	    } else if(ret == CL_SUCCESS) {
		ret = cli_map_scan(*ctx->fmap, pos, filesize, ctx, CL_TYPE_ANY);
		if(ret == CL_VIRUS) {
                    if (!SCAN_ALLMATCHES)
                        return ret;
                    virus_found = 1;
                }
	    }
	}
	if(filesize % 2)
	    filesize++;

	pos += filesize;
    }

 leave:
    if (virus_found != 0)
        return CL_VIRUS;
    return ret;
}

int cli_scancpio_odc(cli_ctx *ctx)
{
	struct cpio_hdr_odc hdr_odc;
	char name[513], buff[12];
	unsigned int file = 0, trailer = 0;
	uint32_t filesize, namesize, hdr_namesize;
	int ret = CL_CLEAN;
	off_t pos = 0;
        int virus_found = 0;


    while(fmap_readn(*ctx->fmap, &hdr_odc, pos, sizeof(hdr_odc)) == sizeof(hdr_odc)) {
	pos += sizeof(hdr_odc);
	if(!hdr_odc.magic[0] && trailer)
	    goto leave;

	if(strncmp(hdr_odc.magic, "070707", 6)) {
	    cli_dbgmsg("cli_scancpio_odc: Invalid magic string\n");
	    ret = CL_EFORMAT;
            goto leave;
	}

	cli_dbgmsg("CPIO: -- File %u --\n", ++file);

	strncpy(buff, hdr_odc.namesize, 6);
	buff[6] = 0;
	if(sscanf(buff, "%o", &hdr_namesize) != 1) {
	    cli_dbgmsg("cli_scancpio_odc: Can't convert name size\n");
	    ret = CL_EFORMAT;
            goto leave;
	}
	if(hdr_namesize) {
	    namesize = MIN(sizeof(name), hdr_namesize);
	    if ((uint32_t)fmap_readn(*ctx->fmap, &name, pos, namesize) != namesize) {
		cli_dbgmsg("cli_scancpio_odc: Can't read file name\n");
		ret = CL_EFORMAT;
                goto leave;
	    }
	    pos += namesize;
	    name[namesize - 1] = 0;
	    sanitname(name);
	    cli_dbgmsg("CPIO: Name: %s\n", name);
	    if(!strcmp(name, "TRAILER!!!"))
		trailer = 1;

	    if(namesize < hdr_namesize)
		pos += hdr_namesize - namesize;
	}

	strncpy(buff, hdr_odc.filesize, 11);
	buff[11] = 0;
	if(sscanf(buff, "%o", &filesize) != 1) {
	    cli_dbgmsg("cli_scancpio_odc: Can't convert file size\n");
	    ret = CL_EFORMAT;
            goto leave;
	}
	cli_dbgmsg("CPIO: Filesize: %u\n", filesize);
	if(!filesize)
	    continue;

	if(cli_matchmeta(ctx, name, filesize, filesize, 0, file, 0, NULL) == CL_VIRUS) {
            if (!SCAN_ALLMATCHES)
                return CL_VIRUS;
            virus_found = 1;
        }


	ret = cli_checklimits("cli_scancpio_odc", ctx, filesize, 0, 0);
	if(ret == CL_EMAXFILES) {
	    goto leave;
	} else if(ret == CL_SUCCESS) {
	    ret = cli_map_scan(*ctx->fmap, pos, filesize, ctx, CL_TYPE_ANY);
	    if(ret == CL_VIRUS) {
                if (!SCAN_ALLMATCHES)
                    return ret;
                virus_found = 1;
            }
	}

	pos += filesize;
    }

 leave:
    if (virus_found != 0)
        return CL_VIRUS;
    return ret;
}

int cli_scancpio_newc(cli_ctx *ctx, int crc)
{
	struct cpio_hdr_newc hdr_newc;
	char name[513], buff[9];
	unsigned int file = 0, trailer = 0;
	uint32_t filesize, namesize, hdr_namesize, pad;
	int ret = CL_CLEAN;
	off_t pos = 0;
        int virus_found = 0;

    memset(name, 0, 513);

    while(fmap_readn(*ctx->fmap, &hdr_newc, pos, sizeof(hdr_newc)) == sizeof(hdr_newc)) {
	pos += sizeof(hdr_newc);
	if(!hdr_newc.magic[0] && trailer)
	    goto leave;

	if((!crc && strncmp(hdr_newc.magic, "070701", 6)) || (crc && strncmp(hdr_newc.magic, "070702", 6))) {
	    cli_dbgmsg("cli_scancpio_newc: Invalid magic string\n");
	    ret = CL_EFORMAT;
            goto leave;
	}

	cli_dbgmsg("CPIO: -- File %u --\n", ++file);

	strncpy(buff, hdr_newc.namesize, 8);
	buff[8] = 0;
	if(sscanf(buff, "%x", &hdr_namesize) != 1) {
	    cli_dbgmsg("cli_scancpio_newc: Can't convert name size\n");
	    ret = CL_EFORMAT;
            goto leave;
	}
	if(hdr_namesize) {
	    namesize = MIN(sizeof(name), hdr_namesize);
	    if ((uint32_t)fmap_readn(*ctx->fmap, &name, pos, namesize) != namesize) {
		cli_dbgmsg("cli_scancpio_newc: Can't read file name\n");
		ret = CL_EFORMAT;
                goto leave;
	    }
	    pos += namesize;
	    name[namesize - 1] = 0;
	    sanitname(name);
	    cli_dbgmsg("CPIO: Name: %s\n", name);
	    if(!strcmp(name, "TRAILER!!!"))
		trailer = 1;

	    pad = (4 - (sizeof(hdr_newc) + hdr_namesize) % 4) % 4;
	    if(namesize < hdr_namesize) {
		if(pad)
		    hdr_namesize += pad;
		pos += hdr_namesize - namesize;
	    } else if(pad)
		pos += pad;
	}

	strncpy(buff, hdr_newc.filesize, 8);
	buff[8] = 0;
	if(sscanf(buff, "%x", &filesize) != 1) {
	    cli_dbgmsg("cli_scancpio_newc: Can't convert file size\n");
	    ret = CL_EFORMAT;
            goto leave;
	}
	cli_dbgmsg("CPIO: Filesize: %u\n", filesize);
	if(!filesize)
	    continue;

	if(cli_matchmeta(ctx, name, filesize, filesize, 0, file, 0, NULL) == CL_VIRUS) {
            if (!SCAN_ALLMATCHES)
                return CL_VIRUS;
            virus_found = 1;
        }

	ret = cli_checklimits("cli_scancpio_newc", ctx, filesize, 0, 0);
	if(ret == CL_EMAXFILES) {
	    goto leave;
	} else if(ret == CL_SUCCESS) {
	    ret = cli_map_scan(*ctx->fmap, pos, filesize, ctx, CL_TYPE_ANY);
	    if(ret == CL_VIRUS) {
                if (!SCAN_ALLMATCHES)
                    return ret;
                virus_found = 1;
            }
	}

	if((pad = filesize % 4))
	    filesize += (4 - pad);

	pos += filesize;
    }

 leave:
    if (virus_found != 0)
        return CL_VIRUS;
    return ret;
}
