/*
 *  Copyright (C) 2007-2009 Sourcefire, Inc.
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
#include "hashtab.h"
#include "fmap.h"
#include "mpool.h"

#define CLI_MATCH_WILDCARD	0xff00
#define CLI_MATCH_CHAR		0x0000
#define CLI_MATCH_IGNORE	0x0100
#define CLI_MATCH_SPECIAL	0x0200
#define CLI_MATCH_NIBBLE_HIGH	0x0300
#define CLI_MATCH_NIBBLE_LOW	0x0400

struct cli_lsig_tdb {
#define CLI_TDB_UINT	0
#define CLI_TDB_RANGE	1
#define CLI_TDB_STR	2
#define CLI_TDB_RANGE2	3
#define CLI_TDB_FTYPE	4
    uint32_t *val, *range;
    char *str;
    uint32_t cnt[3];

    const uint32_t *target;
    const uint32_t *engine, *nos, *ep, *filesize;
    const uint32_t *container;
    /*
    const uint32_t *sectoff, *sectrva, *sectvsz, *sectraw, *sectrsz,
		   *secturva, *sectuvsz, *secturaw, *sectursz;
    */
    const char *icongrp1, *icongrp2;
    uint32_t *macro_ptids;
    uint32_t subsigs;
#ifdef USE_MPOOL
    mpool_t *mempool;
#endif
};

struct cli_bc;
struct cli_ac_lsig {
    uint32_t id;
    char *logic;
    const char *virname;
    struct cli_lsig_tdb tdb;
    unsigned bc_idx;
};

struct cli_matcher {
    unsigned int type;

    /* Extended Boyer-Moore */
    uint8_t *bm_shift;
    struct cli_bm_patt **bm_suffix, **bm_pattab;
    struct cli_hashset md5_sizes_hs;
    uint32_t *soff, soff_len; /* for PE section sigs */
    uint32_t bm_offmode, bm_patterns, bm_reloff_num, bm_absoff_num;

    /* Extended Aho-Corasick */
    uint32_t ac_partsigs, ac_nodes, ac_patterns, ac_lsigs;
    struct cli_ac_lsig **ac_lsigtable;
    struct cli_ac_node *ac_root, **ac_nodetable;
    struct cli_ac_patt **ac_pattable;
    struct cli_ac_patt **ac_reloff;
    uint32_t ac_reloff_num, ac_absoff_num;
    uint8_t ac_mindepth, ac_maxdepth;
    struct filter *filter;

    uint16_t maxpatlen;
    uint8_t ac_only;
#ifdef USE_MPOOL
    mpool_t *mempool;
#endif
};

struct cli_cdb
{
    char	*virname;   /* virus name */
    cli_file_t	ctype;	    /* container type */
    regex_t	name;	    /* filename regex */
    size_t	csize[2];   /* container size (min, max); if csize[0] != csize[1]
			     * then value of 0 makes the field ignored
			     */
    size_t	fsizec[2];  /* file size in container */
    size_t	fsizer[2];  /* real file size */
    int		encrypted;  /* file is encrypted; 2 == ignore */
    int		filepos[2]; /* file position in container */
    int		res1;	    /* reserved / format specific */
    void	*res2;	    /* reserved / format specific */

    struct cli_cdb *next;
};

struct cli_mtarget {
    cli_file_t target;
    const char *name;
    uint8_t idx;    /* idx of matcher */
    uint8_t ac_only;
    uint8_t enable_prefiltering;
};

#define CLI_MTARGETS 10
static const struct cli_mtarget cli_mtargets[CLI_MTARGETS] =  {
    { 0,                    "GENERIC",      0,  0, 1 },
    { CL_TYPE_MSEXE,        "PE",           1,  0, 1 },
    { CL_TYPE_MSOLE2,       "OLE2",         2,  1, 0 },
    { CL_TYPE_HTML,         "HTML",         3,  1, 0 },
    { CL_TYPE_MAIL,         "MAIL",         4,  1, 1 },
    { CL_TYPE_GRAPHICS,     "GRAPHICS",     5,  1, 0 },
    { CL_TYPE_ELF,          "ELF",          6,  1, 0 },
    { CL_TYPE_TEXT_ASCII,   "ASCII",        7,  1, 1 },
    { CL_TYPE_ERROR,        "NOT USED",     8,  1, 0 },
    { CL_TYPE_MACHO,        "MACH-O",       9,  1, 0 }
};

struct cli_target_info {
    off_t fsize;
    struct cli_exe_info exeinfo;
    int8_t status; /* 0 == not initialised, 1 == initialised OK, -1 == error */
};

#define CLI_OFF_ANY         0xffffffff
#define CLI_OFF_NONE	    0xfffffffe
#define CLI_OFF_ABSOLUTE    1
#define CLI_OFF_EOF_MINUS   2
#define CLI_OFF_EP_PLUS     3
#define CLI_OFF_EP_MINUS    4
#define CLI_OFF_SL_PLUS     5
#define CLI_OFF_SX_PLUS     6
#define CLI_OFF_VERSION     7
#define CLI_OFF_MACRO       8

int cli_scanbuff(const unsigned char *buffer, uint32_t length, uint32_t offset, cli_ctx *ctx, cli_file_t ftype, struct cli_ac_data **acdata);

int cli_scandesc(int desc, cli_ctx *ctx, cli_file_t ftype, uint8_t ftonly, struct cli_matched_type **ftoffset, unsigned int acmode);
int cli_fmap_scandesc(cli_ctx *ctx, cli_file_t ftype, uint8_t ftonly, struct cli_matched_type **ftoffset, unsigned int acmode, unsigned char *refhash);
int cli_lsig_eval(cli_ctx *ctx, struct cli_matcher *root, struct cli_ac_data *acdata);
int cli_caloff(const char *offstr, struct cli_target_info *info, fmap_t *map, unsigned int target, uint32_t *offdata, uint32_t *offset_min, uint32_t *offset_max);

int cli_checkfp(unsigned char *digest, size_t size, cli_ctx *ctx);

int cli_matchmeta(cli_ctx *ctx, const char *fname, size_t fsizec, size_t fsizer, int encrypted, int filepos, int res1, void *res2);

#endif
