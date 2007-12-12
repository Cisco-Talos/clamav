/*
 *  Copyright (C) 2002 - 2007 Tomasz Kojm <tkojm@clamav.net>
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

#ifndef __MATCHER_AC_H
#define __MATCHER_AC_H

#include <sys/types.h>

#include "filetypes.h"
#include "cltypes.h"

#define AC_DEFAULT_MIN_DEPTH 2
#define AC_DEFAULT_MAX_DEPTH 3
#define AC_DEFAULT_TRACKLEN 8
extern uint8_t cli_ac_mindepth, cli_ac_maxdepth;

struct cli_ac_data {
    uint32_t partsigs;
    int32_t ***offmatrix;
};

struct cli_ac_alt {
    uint8_t chmode;
    unsigned char *str;
    uint16_t len, num;
    struct cli_ac_alt *next;
};

struct cli_ac_patt {
    uint16_t *pattern, *prefix, length, prefix_length;
    uint8_t depth;
    uint32_t mindist, maxdist;
    char *virname, *offset;
    uint32_t sigid;
    uint16_t parts, partno, alt, alt_pattern;
    struct cli_ac_alt **alttable;
    uint8_t target;
    uint16_t type;
    struct cli_ac_patt *next, *next_same;
};

struct cli_ac_node {
    uint8_t leaf, final;
    struct cli_ac_patt *list;
    struct cli_ac_node **trans, *fail;
};

#include "matcher.h"

int cli_ac_addpatt(struct cli_matcher *root, struct cli_ac_patt *pattern);
int cli_ac_initdata(struct cli_ac_data *data, uint32_t partsigs, uint8_t tracklen);
void cli_ac_freedata(struct cli_ac_data *data);
int cli_ac_scanbuff(const unsigned char *buffer, uint32_t length, const char **virname, const struct cli_matcher *root, struct cli_ac_data *mdata, uint8_t otfrec, uint32_t offset, cli_file_t ftype, int fd, struct cli_matched_type **ftoffset);
int cli_ac_buildtrie(struct cli_matcher *root);
int cli_ac_init(struct cli_matcher *root, uint8_t mindepth, uint8_t maxdepth);
void cli_ac_free(struct cli_matcher *root);
int cli_ac_addsig(struct cli_matcher *root, const char *virname, const char *hexsig, uint32_t sigid, uint16_t parts, uint16_t partno, uint16_t type, uint32_t mindist, uint32_t maxdist, const char *offset, uint8_t target);
void cli_ac_setdepth(uint8_t mindepth, uint8_t maxdepth);

#endif
