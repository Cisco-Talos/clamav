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

#ifndef __MATCHER_H
#define __MATCHER_H

#include <sys/types.h>

#include "clamav.h"
#include "filetypes.h"
#include "others.h"
#include "execs.h"
#include "cltypes.h"
#include "md5.h"

#include "matcher-ac.h"
#include "matcher-bm.h"

#define CLI_MATCH_WILDCARD	0xff00
#define CLI_MATCH_CHAR		0x0000
#define CLI_MATCH_IGNORE	0x0100
#define CLI_MATCH_ALTERNATIVE	0x0200
#define CLI_MATCH_NIBBLE_HIGH	0x0300
#define CLI_MATCH_NIBBLE_LOW	0x0400

struct cli_matcher {
    uint16_t maxpatlen;
    uint8_t ac_only;

    /* Extended Boyer-Moore */
    uint8_t *bm_shift;
    struct cli_bm_patt **bm_suffix;
    uint32_t *soff, soff_len; /* for PE section sigs */

    /* Extended Aho-Corasick */
    uint8_t ac_mindepth, ac_maxdepth;
    struct cli_ac_node *ac_root, **ac_nodetable;
    struct cli_ac_patt **ac_pattable;
    uint32_t ac_partsigs, ac_nodes, ac_patterns;
};

struct cli_md5_node {
    char *virname;
    unsigned char *md5;
    unsigned int size;
    unsigned short fp;
    struct cli_md5_node *next;
};

struct cli_meta_node {
    int csize, size, method;
    unsigned int crc32, fileno, encrypted, maxdepth;
    char *filename, *virname;
    struct cli_meta_node *next;
};

#define CL_TARGET_TABLE_SIZE 7

struct cli_target_info {
    off_t fsize;
    struct cli_exe_info exeinfo;
    int8_t status; /* 0 == not initialised, 1 == initialised OK, -1 == error */
};

int cli_scanbuff(const unsigned char *buffer, uint32_t length, const char **virname, const struct cl_engine *engine, cli_file_t ftype);

int cli_scandesc(int desc, cli_ctx *ctx, uint8_t otfrec, cli_file_t ftype, uint8_t ftonly, struct cli_matched_type **ftoffset);

int cli_validatesig(cli_file_t ftype, const char *offstr, off_t fileoff, struct cli_target_info *info, int desc, const char *virname);

struct cli_md5_node *cli_vermd5(const unsigned char *md5, const struct cl_engine *engine);

off_t cli_caloff(const char *offstr, struct cli_target_info *info, int fd, cli_file_t ftype, int *ret, unsigned int *maxshift);

#endif
