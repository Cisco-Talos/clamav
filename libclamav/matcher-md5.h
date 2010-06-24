/*
 *  Copyright (C) 2007-2010 Sourcefire, Inc.
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

#ifndef __MATCHER_MD5_H
#define __MATCHER_MD5_H

#include "matcher.h"
#include "cltypes.h"

struct cli_md5m_patt {
    unsigned char md5[16];
    uint32_t filesize;
    char *virname;
    struct cli_md5m_patt *next;
};

int cli_md5m_addpatt(struct cli_matcher *root, struct cli_md5m_patt *patt);
int cli_md5m_init(struct cli_matcher *root);
int cli_md5m_scan(const unsigned char *md5, uint32_t filesize, const char **virname, const struct cli_matcher *root);
void cli_md5m_free(struct cli_matcher *root);

#endif
