/*
 *  Copyright (C) 2007-2008 Sourcefire, Inc.
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

#include "mpool.h"

#define CLI_MATCH_WILDCARD	0xff00
#define CLI_MATCH_CHAR		0x0000
#define CLI_MATCH_IGNORE	0x0100
#define CLI_MATCH_ALTERNATIVE	0x0200
#define CLI_MATCH_NIBBLE_HIGH	0x0300
#define CLI_MATCH_NIBBLE_LOW	0x0400

struct cli_lsig_tdb {
#define CLI_TDB_UINT	0
#define CLI_TDB_RANGE	1
#define CLI_TDB_STR	2
#define CLI_TDB_RANGE2	3
    uint32_t *val, *range;
    char *str;
    uint32_t cnt[3];

    const uint32_t *target;
    const uint32_t *engine, *nos, *ep;
    const uint32_t *sectoff, *sectrva, *sectvsz, *sectraw, *sectrsz,
		   *secturva, *sectuvsz, *secturaw, *sectursz;
#ifdef USE_MPOOL
    mpool_t *mempool;
#endif
};

struct cli_ac_lsig {
    uint32_t id;
    char *logic;
    const char *virname;
    struct cli_lsig_tdb tdb;
};

struct cli_matcher {
    /* Extended Boyer-Moore */
    uint8_t *bm_shift;
    struct cli_bm_patt **bm_suffix;
    struct hashset md5_sizes_hs;
    uint32_t *soff, soff_len; /* for PE section sigs */
    uint32_t bm_patterns;

    /* Extended Aho-Corasick */
    uint32_t ac_partsigs, ac_nodes, ac_patterns, ac_lsigs;
    struct cli_ac_lsig **ac_lsigtable;
    struct cli_ac_node *ac_root, **ac_nodetable;
    struct cli_ac_patt **ac_pattable;
    uint8_t ac_mindepth, ac_maxdepth;

    uint16_t maxpatlen;
    uint8_t ac_only;
#ifdef USE_MPOOL
    mpool_t *mempool;
#endif
};

struct cli_meta_node {
    char *filename, *virname;
    struct cli_meta_node *next;
    int csize, size, method;
    unsigned int crc32, fileno, encrypted, maxdepth;
};

struct cli_mtarget {
    cli_file_t target;
    const char *name;
    uint8_t idx;    /* idx of matcher */
    uint8_t ac_only;
};

#define CLI_MTARGETS 9
static const struct cli_mtarget cli_mtargets[CLI_MTARGETS] =  {
    { 0,		    "GENERIC",	    0,	0   },
    { CL_TYPE_MSEXE,	    "PE",	    1,	0   },
    { CL_TYPE_MSOLE2,	    "OLE2",	    2,	1   },
    { CL_TYPE_HTML,	    "HTML",	    3,	1   },
    { CL_TYPE_MAIL,	    "MAIL",	    4,	1   },
    { CL_TYPE_GRAPHICS,	    "GRAPHICS",	    5,	1   },
    { CL_TYPE_ELF,	    "ELF",	    6,	1   },
    { CL_TYPE_TEXT_ASCII,   "ASCII",	    7,	1   },
    { CL_TYPE_PE_DISASM,    "DISASM",	    8,	1   }
};

struct cli_target_info {
    off_t fsize;
    struct cli_exe_info exeinfo;
    int8_t status; /* 0 == not initialised, 1 == initialised OK, -1 == error */
};

int cli_scanbuff(const unsigned char *buffer, uint32_t length, uint32_t offset, cli_ctx *ctx, cli_file_t ftype, struct cli_ac_data **acdata);

int cli_scandesc(int desc, cli_ctx *ctx, cli_file_t ftype, uint8_t ftonly, struct cli_matched_type **ftoffset, unsigned int acmode);

int cli_validatesig(cli_file_t ftype, const char *offstr, off_t fileoff, struct cli_target_info *info, int desc, const char *virname);

off_t cli_caloff(const char *offstr, struct cli_target_info *info, int fd, cli_file_t ftype, int *ret, unsigned int *maxshift);

int cli_checkfp(int fd, cli_ctx *ctx);

#endif
