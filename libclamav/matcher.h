/*
 *  Copyright (C) 2013-2022 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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

/**
 * Initialize a struct cli_target_info so that it's ready to have its exeinfo
 * populated by the call to cli_targetinfo and/or destroyed by
 * cli_targetinfo_destroy.
 *
 * @param info a pointer to the struct cli_target_info to initialize
 */
void cli_targetinfo_init(struct cli_target_info *info);

/**
 * Free resources associated with a struct cli_target_info initialized
 * via cli_targetinfo_init
 *
 * @param info a pointer to the struct cli_target_info to destroy
 */
void cli_targetinfo_destroy(struct cli_target_info *info);

#include "matcher-ac.h"
#include "matcher-bm.h"
#include "matcher-hash.h"
#include "matcher-pcre.h"
#include "matcher-byte-comp.h"
#include "regex_pcre.h"
#include "fmap.h"
#include "mpool.h"

// clang-format off

#define CLI_MATCH_METADATA    0xff00
#define CLI_MATCH_WILDCARD    0x0f00
#define CLI_MATCH_CHAR        0x0000
#define CLI_MATCH_NOCASE      0x1000
#define CLI_MATCH_IGNORE      0x0100
#define CLI_MATCH_SPECIAL     0x0200
#define CLI_MATCH_NIBBLE_HIGH 0x0300
#define CLI_MATCH_NIBBLE_LOW  0x0400

typedef enum tdb_type {
    CLI_TDB_UINT,
    CLI_TDB_RANGE,
    CLI_TDB_STR,
    CLI_TDB_RANGE2,
    CLI_TDB_FTYPE,
    CLI_TDB_FTYPE_EXPR
} tdb_type_t;

struct cli_lsig_tdb {
    uint32_t       *val, *range;
    char           *str;
    tdb_type_t     cnt[3];
    uint32_t       subsigs;

    const uint32_t *target;
    const uint32_t *engine, *nos, *ep, *filesize;
    const uint32_t *container, *handlertype;
    const uint32_t *intermediates;
    /*
    const uint32_t *sectoff, *sectrva, *sectvsz, *sectraw, *sectrsz,
                   *secturva, *sectuvsz, *secturaw, *sectursz;
    */
    const char     *icongrp1, *icongrp2;
    uint32_t       *macro_ptids;
#ifdef USE_MPOOL
    mpool_t        *mempool;
#else
    void           *_padding_mempool;
#endif
};

// clang-format on

#define CLI_LSIG_FLAG_PRIVATE 0x01

typedef enum lsig_type {
    CLI_LSIG_NORMAL,
    CLI_YARA_NORMAL,
    CLI_YARA_OFFSET
} lsig_type_t;

struct cli_bc;
struct cli_ac_lsig {
    uint32_t id;
    unsigned bc_idx;
    lsig_type_t type;
    uint8_t flag;
    union {
        char *logic;
        uint8_t *code_start;
    } u;
    char *virname;
    struct cli_lsig_tdb tdb;
};

typedef void *fuzzyhashmap_t;

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

    /* Fuzzy Image Hash */
    fuzzyhashmap_t fuzzy_hashmap;

    /* Bytecode Tracker */
    uint32_t linked_bcs;

#ifdef USE_MPOOL
    mpool_t *mempool;
#else
    void *_padding_mempool;
#endif
};

struct cli_cdb {
    char *virname;           /* virus name */
    cli_file_t ctype;        /* container type */
    regex_t name;            /* filename regex */
    size_t csize[2];         /* container size (min, max); if csize[0] != csize[1]
                              * then value of 0 makes the field ignored
                              */
    size_t fsizec[2];        /* file size in container */
    size_t fsizer[2];        /* real file size */
    int encrypted;           /* file is encrypted; 2 == ignore */
    unsigned int filepos[2]; /* file position in container */
    int res1;                /* reserved / format specific */
    void *res2;              /* reserved / format specific */

    struct cli_cdb *next;
};

typedef enum {
    TARGET_GENERIC  = 0,
    TARGET_PE       = 1,
    TARGET_OLE2     = 2,
    TARGET_HTML     = 3,
    TARGET_MAIL     = 4,
    TARGET_GRAPHICS = 5,
    TARGET_ELF      = 6,
    TARGET_ASCII    = 7,
    TARGET_NOT_USED = 8,
    TARGET_MACHO    = 9,
    TARGET_PDF      = 10,
    TARGET_FLASH    = 11,
    TARGET_JAVA     = 12,
    TARGET_INTERNAL = 13,
    TARGET_OTHER    = 14,
} cli_target_t;

#define CLI_MAX_TARGETS 10 /* maximum filetypes for a specific target */
struct cli_mtarget {
    cli_file_t target[CLI_MAX_TARGETS];
    const char *name;
    cli_target_t idx; /* idx of matcher */
    uint8_t ac_only;
    uint8_t enable_prefiltering;
    uint8_t target_count; /* must be synced with non-zero values in the target array */
};

#define CLI_MTARGETS 15
static const struct cli_mtarget cli_mtargets[CLI_MTARGETS] = {
    /* All types for target, name, idx, ac_only, pre-filtering?, # of types */
    {{CL_TYPE_ANY, 0, 0, 0, 0, 0, 0, 0, 0, 0}, "GENERIC", TARGET_GENERIC, 0, 1, 1},
    {{CL_TYPE_MSEXE, 0, 0, 0, 0, 0, 0, 0, 0, 0}, "PE", TARGET_PE, 0, 1, 1},
    {{CL_TYPE_MSOLE2, 0, 0, 0, 0, 0, 0, 0, 0, 0}, "OLE2", TARGET_OLE2, 1, 0, 1},
    {{CL_TYPE_HTML, 0, 0, 0, 0, 0, 0, 0, 0, 0}, "HTML", TARGET_HTML, 1, 0, 1},
    {{CL_TYPE_MAIL, 0, 0, 0, 0, 0, 0, 0, 0, 0}, "MAIL", TARGET_MAIL, 1, 1, 1},
    {{CL_TYPE_GRAPHICS, CL_TYPE_GIF, CL_TYPE_PNG, CL_TYPE_JPEG, CL_TYPE_TIFF, 0, 0, 0, 0, 0}, "GRAPHICS", TARGET_GRAPHICS, 1, 0, 5},
    {{CL_TYPE_ELF, 0, 0, 0, 0, 0, 0, 0, 0, 0}, "ELF", TARGET_ELF, 1, 0, 1},
    {{CL_TYPE_TEXT_ASCII, 0, 0, 0, 0, 0, 0, 0, 0, 0}, "ASCII", TARGET_ASCII, 1, 1, 1},
    {{CL_TYPE_ERROR, 0, 0, 0, 0, 0, 0, 0, 0, 0}, "NOT USED", TARGET_NOT_USED, 1, 0, 1},
    {{CL_TYPE_MACHO, CL_TYPE_MACHO_UNIBIN, 0, 0, 0, 0, 0, 0, 0, 0}, "MACH-O", TARGET_MACHO, 1, 0, 2},
    {{CL_TYPE_PDF, 0, 0, 0, 0, 0, 0, 0, 0, 0}, "PDF", TARGET_PDF, 1, 0, 1},
    {{CL_TYPE_SWF, 0, 0, 0, 0, 0, 0, 0, 0, 0}, "FLASH", TARGET_FLASH, 1, 0, 1},
    {{CL_TYPE_JAVA, 0, 0, 0, 0, 0, 0, 0, 0, 0}, "JAVA", TARGET_JAVA, 1, 0, 1},
    {{CL_TYPE_INTERNAL, 0, 0, 0, 0, 0, 0, 0, 0, 0}, "INTERNAL", TARGET_INTERNAL, 1, 0, 1},
    {{CL_TYPE_OTHER, 0, 0, 0, 0, 0, 0, 0, 0, 0}, "OTHER", TARGET_OTHER, 1, 0, 1}};

// clang-format off

#define CLI_OFF_ANY         0xffffffff
#define CLI_OFF_NONE        0xfffffffe
#define CLI_OFF_ABSOLUTE    1
#define CLI_OFF_EOF_MINUS   2
#define CLI_OFF_EP_PLUS     3
#define CLI_OFF_EP_MINUS    4
#define CLI_OFF_SL_PLUS     5
#define CLI_OFF_SX_PLUS     6
#define CLI_OFF_VERSION     7
#define CLI_OFF_MACRO       8
#define CLI_OFF_SE          9

// clang-format on

/**
 * @brief Non-magic scan matching using a file buffer for input.  Older API
 *
 * This function is lower-level than the *magic_scan* functions from scanners.
 * This function does not perform file type magic identification and does not use
 * the file format scanners.
 *
 * Unlike the similar functions `cli_scan_desc()` and `cli_scan_fmap()` (below),
 * this function:
 *
 * - REQUIRES a call to `cli_exp_eval()` after the match to evaluate logical
 *   signatures and yara rules.
 *
 * - Does NOT support filetype detection.
 *
 * - Does NOT perform hash-based matching.
 *
 * - Does NOT support AC, BM, or PCRE relative-offset signature matching.
 *
 * - DOES support passing in externally initialized AC matcher data
 *
 * @param buffer            The buffer to be matched.
 * @param length            The length of the buffer or amount of bytets to match.
 * @param offset            Offset into the buffer from which to start matching.
 * @param ctx               The scanning context.
 * @param ftype             If specified, may limit signature matching trie by target type corresponding with the specified CL_TYPE
 * @param[in,out] acdata    (optional) A list of pattern maching data structs to contain match results, one for generic signatures and one for target-specific signatures.
 *                          If not provided, the matcher results are lost, outside of this function's return value.
 *                          Required if you want to evaluate logical expressions afterwards.
 * @return cl_error_t
 */
cl_error_t cli_scan_buff(const unsigned char *buffer, uint32_t length, uint32_t offset, cli_ctx *ctx, cli_file_t ftype, struct cli_ac_data **acdata);

/**
 * @brief Non-magic scan matching using a file descriptor for input.
 *
 * This function is lower-level than the *magic_scan* functions from scanners.
 * This function does not perform file type magic identification and does not use
 * the file format scanners.
 *
 * This function does signature matching for generic signatures, target-specific
 * signatures, and file type recognition signatures to detect embedded files or
 * to correct the current file type.
 *
 * This function is just a wrapper for `cli_scan_fmap()` that converts the file
 * to an fmap and scans it.
 *
 * @param desc          File descriptor to be used for input
 * @param ctx           The scanning context.
 * @param ftype         If specified, may limit signature matching trie by target type corresponding with the specified CL_TYPE
 * @param filetype_only Boolean indicating if the scan is for file-type detection only.
 * @param[out] ftoffset (optional) A list of file type signature matches with their corresponding offsets. If provided, will output the file type signature matches.
 * @param acmode        Use AC_SCAN_VIR and AC_SCAN_FT to set scanning modes.
 * @param[out] acres    A list of cli_ac_result AC pattern matching results.
 * @param name          (optional) Original name of the file (to set fmap name metadata)
 * @return cl_error_t
 */
cl_error_t cli_scan_desc(int desc, cli_ctx *ctx, cli_file_t ftype, bool filetype_only, struct cli_matched_type **ftoffset, unsigned int acmode, struct cli_ac_result **acres, const char *name);

/**
 * @brief Non-magic scan matching of the current fmap in the scan context.  Newer API.
 *
 * This function is lower-level than the *magic_scan* functions from scanners.
 * This function does not perform file type magic identification and does not use
 * the file format scanners.
 *
 * This function does signature matching for generic signatures, target-specific
 * signatures, and file type recognition signatures to detect embedded files or
 * to correct the current file type.
 *
 * This API will invoke cli_exp_eval() for you.
 *
 * @param ctx           The scanning context.
 * @param ftype         If specified, may limit signature matching trie by target type corresponding with the specified CL_TYPE
 * @param filetype_only Boolean indicating if the scan is for file-type detection only.
 * @param[out] ftoffset (optional) A list of file type signature matches with their corresponding offsets. If provided, will output the file type signature matches.
 * @param acmode        Use AC_SCAN_VIR and AC_SCAN_FT to set scanning modes.
 * @param[out] acres    A list of cli_ac_result AC pattern matching results.
 * @param refhash       MD5 hash of the current file, used to save time creating hashes and to limit scan recursion for the HandlerType logical signature FTM feature.
 * @return cl_error_t
 */
cl_error_t cli_scan_fmap(cli_ctx *ctx, cli_file_t ftype, bool filetype_only, struct cli_matched_type **ftoffset, unsigned int acmode, struct cli_ac_result **acres, unsigned char *refhash);

/**
 * @brief Evaluate logical signatures and yara rules given the AC matching results
 * from cli_scan_buff() / matcher_run().
 *
 * @param ctx           The scanning context.
 * @param root          The AC trie root to match with.
 * @param acdata        AC match results for a specific AC trie.
 * @param target_info   File metadata used to evaluate logical sig and yara rule options.
 * @param hash          Reference hash of the current file, used to limit recursion for the HandlerType logical signature FTM feature.
 * @return cl_error_t
 */
cl_error_t cli_exp_eval(cli_ctx *ctx, struct cli_matcher *root, struct cli_ac_data *acdata, struct cli_target_info *target_info, const char *hash);

cl_error_t cli_caloff(const char *offstr, const struct cli_target_info *info, unsigned int target, uint32_t *offdata, uint32_t *offset_min, uint32_t *offset_max);

/**
 * @brief Determine if an alert is a known false positive, using each fmap in the the ctx->container stack to check MD5, SHA1, and SHA256 hashes.
 *
 * @param ctx           The scanning context.
 * @param vname         (Optional) The name of the signature alert.
 * @return cl_error_t   CL_CLEAN If an allow-list hash matches with one of the fmap hashes in the scan recursion stack.
 *                      CL_VIRUS If no allow-list hash matches.
 */
cl_error_t cli_check_fp(cli_ctx *ctx, const char *vname);

cl_error_t cli_matchmeta(cli_ctx *ctx, const char *fname, size_t fsizec, size_t fsizer, int encrypted, unsigned int filepos, int res1, void *res2);

/** Parse the executable headers and, if successful, populate exeinfo
 *
 * If target refers to a supported executable file type, the exe header
 * will be parsed and, if successful, info->status will be set to 1.
 * If parsing the exe header fails, info->status will be set to -1.
 * The caller MUST destroy info via a call to cli_targetinfo_destroy
 * regardless of what info->status is set to.
 *
 * @param info A structure to populate with info from the exe header. This
 *             MUST be initialized via cli_targetinfo_init prior to calling
 * @param target the target executable file type. Possible values are:
 *               - 1 - PE32 / PE32+
 *               - 6 - ELF
 *               - 9 - MachO
 * @param ctx The current scan context
 */
void cli_targetinfo(struct cli_target_info *info, unsigned int target, cli_ctx *ctx);

#endif
