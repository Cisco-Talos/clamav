/*
 *  Copyright (C) 2007 Tomasz Kojm <tkojm@clamav.net>
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

#ifndef __MIRMAN_H
#define __MIRMAN_H

#include "libclamav/cltypes.h"

struct mirdat_ip {
    uint32_t ip;	    /* IP address */
    uint32_t atime;	    /* last access time */
    uint32_t succ;	    /* number of successful downloads from this ip */
    uint32_t fail;	    /* number of failures */
    uint8_t ignore;	    /* ignore flag */
    char res[32];	    /* reserved */
};

struct mirdat {
    uint8_t active;
    unsigned int num;
    uint32_t currip;
    uint32_t dbflevel;
    struct mirdat_ip *mirtab;
};

int mirman_read(const char *file, struct mirdat *mdat, uint8_t active);
int mirman_check(uint32_t ip, struct mirdat *mdat);
int mirman_update(uint32_t ip, struct mirdat *mdat, uint8_t broken);
void mirman_list(const struct mirdat *mdat);
int mirman_write(const char *file, struct mirdat *mdat);
void mirman_free(struct mirdat *mdat);

#endif
