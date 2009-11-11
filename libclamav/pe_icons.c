/*
 *  Copyright (C) 2009 Sourcefire, Inc.
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

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include "pe_icons.h"
#include "others.h"


#define EC32(x) le32_to_host(x)

struct GICONS {
    unsigned int cnt;
    uint32_t lastg;
    uint32_t rvas[100];
};

static int groupicon(void *ptr, uint32_t type, uint32_t name, uint32_t lang, uint32_t rva) {
    struct GICONS *gicons = ptr;
    type = type; lang = lang;
    cli_warnmsg("got group %u\n", name);
    if(!gicons->cnt || gicons->lastg == name) {
	gicons->rvas[gicons->cnt] = rva;
	gicons->cnt++;
	gicons->lastg = name;
	if(gicons->cnt < 100)
	    return 0;
    }
    return 1;
}

struct ICONS {
    unsigned int cnt;
    uint32_t rvas[100];
};

static int icon(void *ptr, uint32_t type, uint32_t name, uint32_t lang, uint32_t rva) {
    struct ICONS *icons = ptr;
    type = type; lang = lang;
    cli_warnmsg("got icon %u\n", name);
    if(icons->cnt > 100) 
	return 1;
    icons->rvas[icons->cnt] = rva;
    icons->cnt++;
    return 0;
}


int scanicon(uint32_t resdir_rva, cli_ctx *ctx, struct cli_exe_section *exe_sections, uint16_t nsections, uint32_t hdr_size) {
    struct GICONS gicons;
    struct ICONS icons;
    unsigned int curicon, err;
    fmap_t *map = *ctx->fmap;

    gicons.cnt = 0;
    icons.cnt = 0;
    findres(14, 0xffffffff, resdir_rva, ctx, exe_sections, nsections, hdr_size, groupicon, &gicons);
	
    for(curicon=0; curicon<gicons.cnt; curicon++) {
	uint8_t *grp = fmap_need_off_once(map, cli_rawaddr(gicons.rvas[curicon], exe_sections, nsections, &err, map->len, hdr_size), 16);
	if(grp && !err) {
	    uint32_t gsz = cli_readint32(grp + 4);
	    if(gsz>6) {
		uint32_t icnt;
		struct {
		    uint8_t w;
		    uint8_t h;
		    uint8_t palcnt;
		    uint8_t rsvd;
		    uint16_t planes;
		    uint16_t depth;
		    uint32_t sz;
		    uint16_t id;
		} *dir;
		
		grp = fmap_need_off_once(map, cli_rawaddr(cli_readint32(grp), exe_sections, nsections, &err, map->len, hdr_size), gsz);
		if(grp && !err) {
		    icnt = cli_readint32(grp+2) >> 16;
		    grp+=6;
		    gsz-=6;

		    while(icnt && gsz >= 14) {
			dir = grp;
			cli_warnmsg("Icongrp @%x - %ux%ux%u - (id=%x, rsvd=%u, planes=%u, palcnt=%u, sz=%x)\n", gicons.rvas[curicon], dir->w, dir->h, dir->depth, dir->id, dir->planes, dir->palcnt, dir->rsvd, dir->sz);
			findres(3, dir->id, resdir_rva, ctx, exe_sections, nsections, hdr_size, icon, &icons);
			grp += 14;
			gsz -= 14;
		    }
		}
	    }
	}
    }

    for(curicon=0; curicon<icons.cnt; curicon++)
	cli_warnmsg("Icon %x is @%x\n", curicon, icons.rvas[curicon]);
}
