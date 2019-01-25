/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
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

struct cli_target_info {
    off_t fsize;
    struct cli_exe_info exeinfo;
    int status; /* 0 == not initialised, 1 == initialised OK, -1 == error */
};

#include "matcher-ac.h"
#include "matcher-bm.h"
#include "matcher-hash.h"
#include "matcher-pcre.h"
#include "matcher-byte-comp.h"
#include "regex_pcre.h"
#include "fmap.h"
#include "mpool.h"

#define CLI_MATCH_METADATA	0xff00
#define CLI_MATCH_WILDCARD	0x0f00
#define CLI_MATCH_CHAR		0x0000
#define CLI_MATCH_NOCASE	0x1000
#define CLI_MATCH_IGNORE	0x0100
#define CLI_MATCH_SPECIAL	0x0200
#define CLI_MATCH_NIBBLE_HIGH	0x0300
#define CLI_MATCH_NIBBLE_LOW	0x0400

struct cli_lsig_tdb {
#define CLI_TDB_UINT		0
#define CLI_TDB_RANGE		1
#define CLI_TDB_STR		2
#define CLI_TDB_RANGE2		3
#define CLI_TDB_FTYPE		4
#define CLI_TDB_FTYPE_EXPR	5
    uint32_t *val, *range;
    char *str;
    uint32_t cnt[3];
    uint32_t subsigs;

    const uint32_t *target;
    const uint32_t *engine, *nos, *ep, *filesize;
    const uint32_t *container, *handlertype;
    const uint32_t *intermediates;
    /*
    const uint32_t *sectoff, *sectrva, *sectvsz, *sectraw, *sectrsz,
		   *secturva, *sectuvsz, *secturaw, *sectursz;
    */
    const char *icongrp1, *icongrp2;
    uint32_t *macro_ptids;
#ifdef USE_MPOOL
    mpool_t *mempool;
#endif
};

#define CLI_LSIG_FLAG_PRIVATE 0x01

struct cli_bc;
struct cli_ac_lsig {
#define CLI_LSIG_NORMAL 0
#define CLI_YARA_NORMAL 1
#define CLI_YARA_OFFSET 2
    uint32_t id;
    unsigned bc_idx;
    uint8_t type;
    uint8_t flag;
    union {
        char *logic;
        uint8_t *code_start;
    } u;
    const char *virname;
    struct cli_lsig_tdb tdb;
};

struct cli_matcher {
    unsigned int type;

    /* Extended Boyer-Moore */
    uint8_t *bm_shift;
    struct cli_bm_patt **bm_suffix, **bm_pattab;
    uint32_t *soff, soff_len; /* for PE section sigs */
    uint32_t bm_offmode, bm_patterns, bm_reloff_num, bm_absoff_num;

    /* HASH */
    struct cli_hash_patt hm;
    struct cli_hash_wild hwild;

    /* Extended Aho-Corasick */
    uint32_t ac_partsigs, ac_nodes, ac_lists, ac_patterns, ac_lsigs;
    struct cli_ac_lsig **ac_lsigtable;
    struct cli_ac_node *ac_root, **ac_nodetable;
    struct cli_ac_list **ac_listtable;
    struct cli_ac_patt **ac_pattable;
    struct cli_ac_patt **ac_reloff;
    uint32_t ac_reloff_num, ac_absoff_num;
    uint8_t ac_mindepth, ac_maxdepth;
    struct filter *filter;

    uint16_t maxpatlen;
    uint8_t ac_only;

    /* Perl-Compiled Regular Expressions */
#if HAVE_PCRE
    uint32_t pcre_metas;
    struct cli_pcre_meta **pcre_metatable;
    uint32_t pcre_reloff_num, pcre_absoff_num;
#endif

    /* Byte Compare */
    uint32_t bcomp_metas;
    struct cli_bcomp_meta **bcomp_metatable;

    /* Bytecode Tracker */
    uint32_t linked_bcs;

#ifdef USE_MPOOL
    mpool_t *mempool;
#endif
};

struct cli_cdb
{
    char	        *virname;   /* virus name */
    cli_file_t	    ctype;	    /* container type */
    regex_t	        name;	    /* filename regex */
    size_t	        csize[2];   /* container size (min, max); if csize[0] != csize[1]
			                     * then value of 0 makes the field ignored
			                     */
    size_t	        fsizec[2];  /* file size in container */
    size_t	        fsizer[2];  /* real file size */
    int		        encrypted;  /* file is encrypted; 2 == ignore */
    unsigned int    filepos[2]; /* file position in container */
    int		        res1;	    /* reserved / format specific */
    void	        *res2;	    /* reserved / format specific */

    struct cli_cdb *next;
};

#define CLI_MAX_TARGETS 2 /* maximum filetypes for a specific target */
struct cli_mtarget {
    cli_file_t target[CLI_MAX_TARGETS];
    const char *name;
    uint8_t idx;    /* idx of matcher */
    uint8_t ac_only;
    uint8_t enable_prefiltering;
    uint8_t target_count; /* must be synced with non-zero values in the target array */
};

#define CLI_MTARGETS 15
static const struct cli_mtarget cli_mtargets[CLI_MTARGETS] =  {
    { {0, 0},                                   "GENERIC",      0,  0, 1, 1 },
    { {CL_TYPE_MSEXE, 0},                       "PE",           1,  0, 1, 1 },
    { {CL_TYPE_MSOLE2, 0},                      "OLE2",         2,  1, 0, 1 },
    { {CL_TYPE_HTML, 0},                        "HTML",         3,  1, 0, 1 },
    { {CL_TYPE_MAIL, 0},                        "MAIL",         4,  1, 1, 1 },
    { {CL_TYPE_GRAPHICS, 0},                    "GRAPHICS",     5,  1, 0, 1 },
    { {CL_TYPE_ELF, 0},                         "ELF",          6,  1, 0, 1 },
    { {CL_TYPE_TEXT_ASCII, 0},                  "ASCII",        7,  1, 1, 1 },
    { {CL_TYPE_ERROR, 0},                       "NOT USED",     8,  1, 0, 1 },
    { {CL_TYPE_MACHO, CL_TYPE_MACHO_UNIBIN},    "MACH-O",       9,  1, 0, 2 },
    { {CL_TYPE_PDF, 0},                         "PDF",         10,  1, 0, 1 },
    { {CL_TYPE_SWF, 0},                         "FLASH",       11,  1, 0, 1 },
    { {CL_TYPE_JAVA, 0},                        "JAVA",        12,  1, 0, 1 },
    { {CL_TYPE_INTERNAL, 0},                    "INTERNAL",    13,  1, 0, 1 },
    { {CL_TYPE_OTHER, 0},                       "OTHER",       14,  1, 0, 1 }
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
#define CLI_OFF_SE	    9

int cli_scanbuff(const unsigned char *buffer, uint32_t length, uint32_t offset, cli_ctx *ctx, cli_file_t ftype, struct cli_ac_data **acdata);

int cli_scandesc(int desc, cli_ctx *ctx, cli_file_t ftype, uint8_t ftonly, struct cli_matched_type **ftoffset, unsigned int acmode, struct cli_ac_result **acres);
int cli_fmap_scandesc(cli_ctx *ctx, cli_file_t ftype, uint8_t ftonly, struct cli_matched_type **ftoffset, unsigned int acmode, struct cli_ac_result **acres, unsigned char *refhash);
int cli_exp_eval(cli_ctx *ctx, struct cli_matcher *root, struct cli_ac_data *acdata, struct cli_target_info *target_info, const char *hash);
int cli_caloff(const char *offstr, const struct cli_target_info *info, unsigned int target, uint32_t *offdata, uint32_t *offset_min, uint32_t *offset_max);

int cli_checkfp(unsigned char *digest, size_t size, cli_ctx *ctx);
int cli_checkfp_virus(unsigned char *digest, size_t size, cli_ctx *ctx, const char * vname);

int cli_matchmeta(cli_ctx *ctx, const char *fname, size_t fsizec, size_t fsizer, int encrypted, unsigned int filepos, int res1, void *res2);

void cli_targetinfo(struct cli_target_info *info, unsigned int target, fmap_t *map);

#endif
