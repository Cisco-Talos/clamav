/*
 *  Copyright (C) 2004 - 2005 Tomasz Kojm <tkojm@clamav.net>
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

#ifndef __MATCHER_BM_H
#define __MATCHER_BM_H

#include "matcher.h"
#include "filetypes.h"
#include "cltypes.h"

struct cli_bm_patt {
    unsigned char *pattern, *prefix;
    uint16_t length, prefix_length;
    char *virname, *offset;
    uint8_t target;
    struct cli_bm_patt *next;
    uint16_t cnt;
};

int cli_bm_addpatt(struct cli_matcher *root, struct cli_bm_patt *pattern);
int cli_bm_init(struct cli_matcher *root);
int cli_bm_scanbuff(const unsigned char *buffer, uint32_t length, const char **virname, const struct cli_matcher *root, uint32_t offset, cli_file_t ftype, int fd);
void cli_bm_free(struct cli_matcher *root);

#endif
