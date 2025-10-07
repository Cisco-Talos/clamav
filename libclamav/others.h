/*
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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

#include "matcher.h"

#ifndef __OTHERS_H_LC
#define __OTHERS_H_LC

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#if HAVE_PTHREAD_H
#include <pthread.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include <json.h>

#include "clamav.h"
#include "other_types.h"
#include "dconf.h"
#include "filetypes.h"
#include "fmap.h"
#include "regex/regex.h"
#include "bytecode.h"
#include "bytecode_api.h"
#include "events.h"
#include "crtmgr.h"
#include "scan_layer.h"

#include "unrar_iface.h"

#ifdef HAVE_YARA
#include "yara_clam.h"
#endif

#define CLAMAV_MIN_XMLREADER_FLAGS (XML_PARSE_NOERROR | XML_PARSE_NONET)

/*
 * CL_FLEVEL is the signature f-level specific to the current code and
 *	     should never be modified
 * CL_FLEVEL_DCONF is used in the dconf module and can be bumped by
 * distribution packagers provided they fix *all* security issues found
 * in the old versions of ClamAV. Updating CL_FLEVEL_DCONF will result
 * in re-enabling affected modules.
 */

#define CL_FLEVEL 240
#define CL_FLEVEL_DCONF CL_FLEVEL
#define CL_FLEVEL_SIGTOOL CL_FLEVEL

extern uint8_t cli_debug_flag;
extern uint8_t cli_always_gen_section_hash;

/*
 * CLI_ISCONTAINED(bb, bb_size, sb, sb_size) checks if sb (small buffer) is
 * within bb (big buffer).
 *
 * bb and sb are pointers (or offsets) for the main buffer and the
 * sub-buffer respectively, and bb_size and sb_size are their sizes
 *
 * The macro can be used to protect against wraps.
 */
#define CLI_ISCONTAINED(bb, bb_size, sb, sb_size)                            \
    ((size_t)(bb_size) > 0 && (size_t)(sb_size) > 0 &&                       \
     (size_t)(sb_size) <= (size_t)(bb_size) &&                               \
     (size_t)(sb) >= (size_t)(bb) &&                                         \
     (size_t)(sb) + (size_t)(sb_size) <= (size_t)(bb) + (size_t)(bb_size) && \
     (size_t)(sb) + (size_t)(sb_size) > (size_t)(bb) &&                      \
     (size_t)(sb) < (size_t)(bb) + (size_t)(bb_size))

/*
 * CLI_ISCONTAINED_0_TO(bb_size, sb, sb_size) checks if sb (small offset) is
 * within bb (big offset) where the big offset always starts at 0.
 *
 * bb and sb are offsets for the main buffer and the
 * sub-buffer respectively, and bb_size and sb_size are their sizes
 *
 * The macro can be used to protect against wraps.
 *
 * CLI_ISCONTAINED_0_TO is the same as CLI_ISCONTAINED except that `bb` is gone
 * and assumed ot be zero.
 */
#define CLI_ISCONTAINED_0_TO(bb_size, sb, sb_size)            \
    ((size_t)(bb_size) > 0 && (size_t)(sb_size) > 0 &&        \
     (size_t)(sb_size) <= (size_t)(bb_size) &&                \
     (size_t)(sb) + (size_t)(sb_size) <= (size_t)(bb_size) && \
     (size_t)(sb) < (size_t)(bb_size))

/*
 * CLI_ISCONTAINED_2(bb, bb_size, sb, sb_size) checks if sb (small buffer) is
 * within bb (big buffer).
 *
 * CLI_ISCONTAINED_2 is the same as CLI_ISCONTAINED except that it allows for
 * small-buffers with sb_size == 0.
 */
#define CLI_ISCONTAINED_2(bb, bb_size, sb, sb_size)                          \
    ((size_t)(bb_size) > 0 &&                                                \
     (size_t)(sb_size) <= (size_t)(bb_size) &&                               \
     (size_t)(sb) >= (size_t)(bb) &&                                         \
     (size_t)(sb) + (size_t)(sb_size) <= (size_t)(bb) + (size_t)(bb_size) && \
     (size_t)(sb) + (size_t)(sb_size) >= (size_t)(bb) &&                     \
     (size_t)(sb) <= (size_t)(bb) + (size_t)(bb_size))

/*
 * CLI_ISCONTAINED_2(bb, bb_size, sb, sb_size) checks if sb (small buffer) is
 * within bb (big buffer).
 *
 * CLI_ISCONTAINED_2 is the same as CLI_ISCONTAINED except that it allows for
 * small-buffers with sb_size == 0.
 *
 * CLI_ISCONTAINED_2_0_TO is the same as CLI_ISCONTAINED_2 except that `bb` is gone
 * and assumed ot be zero.
 */
#define CLI_ISCONTAINED_2_0_TO(bb_size, sb, sb_size)          \
    ((size_t)(bb_size) > 0 &&                                 \
     (size_t)(sb_size) <= (size_t)(bb_size) &&                \
     (size_t)(sb) + (size_t)(sb_size) <= (size_t)(bb_size) && \
     (size_t)(sb) <= (size_t)(bb_size))

#define CLI_MAX_ALLOCATION (1024 * 1024 * 1024)

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h> /* for NAME_MAX */
#endif

/* Maximum filenames under various systems - njh */
#ifndef NAME_MAX  /* e.g. Linux */
#ifdef MAXNAMELEN /* e.g. Solaris */
#define NAME_MAX MAXNAMELEN
#else
#ifdef FILENAME_MAX /* e.g. SCO */
#define NAME_MAX FILENAME_MAX
#else
#define NAME_MAX 256
#endif
#endif
#endif

#if NAME_MAX < 256
#undef NAME_MAX
#define NAME_MAX 256
#endif

typedef struct bitset_tag {
    unsigned char *bitset;
    unsigned long length;
} bitset_t;

/* internal clamav context */
typedef struct cli_ctx_tag {
    char *target_filepath;   /* (optional) The filepath of the original scan target. */
    char *this_layer_tmpdir; /* Pointer to current temporary directory, MAY vary with recursion depth. For convenience. */
    uint64_t *scanned;
    const struct cli_matcher *root;
    const struct cl_engine *engine;
    uint64_t scansize;
    struct cl_scan_options *options;
    uint32_t scannedfiles;
    unsigned int corrupted_input;      /* Setting this flag will prevent the PE parser from reporting "broken executable" for unpacked/reconstructed files that may not be 100% to spec. */
    cli_scan_layer_t *recursion_stack; /* Array of recursion levels used as a stack. */
    uint32_t recursion_stack_size;     /* stack size must == engine->max_recursion_level */
    uint32_t recursion_level;          /* Index into recursion_stack; current fmap recursion level from start of scan. */
    evidence_t this_layer_evidence;    /* Pointer to current evidence in recursion_stack, varies with recursion depth. For convenience. */
    fmap_t *fmap;                      /* Pointer to current fmap in recursion_stack, varies with recursion depth. For convenience. */
    size_t object_count;               /* Counter for number of unique entities/contained files (including normalized files) processed. */
    struct cli_dconf *dconf;
    bitset_t *hook_lsig_matches;
    void *cb_ctx;
    cli_events_t *perf;
    struct json_object *metadata_json;            /* Top level metadata JSON object for the whole scan. */
    struct json_object *this_layer_metadata_json; /* Pointer to current metadata JSON object in recursion_stack, varies with recursion depth. For convenience. */
    struct timeval time_limit;
    bool limit_exceeded; /* To guard against alerting on limits exceeded more than once, or storing that in the JSON metadata more than once. */
    bool abort_scan;     /* So we can guarantee a scan is aborted, even if CL_ETIMEOUT/etc. status is lost in the scan recursion stack. */
} cli_ctx;

#define STATS_ANON_UUID "5b585e8f-3be5-11e3-bf0b-18037319526c"
#define STATS_MAX_SAMPLES 50
#define STATS_MAX_MEM 1024 * 1024

typedef struct cli_flagged_sample {
    char **virus_name;
    char md5[MD5_HASH_SIZE];
    uint32_t size; /* A size of zero means size is unavailable (why would this ever happen?) */
    uint32_t hits;
    stats_section_t *sections;

    struct cli_flagged_sample *prev;
    struct cli_flagged_sample *next;
} cli_flagged_sample_t;

typedef struct cli_clamav_intel {
    char *hostid;
    char *host_info;
    cli_flagged_sample_t *samples;
    uint32_t nsamples;
    uint32_t maxsamples;
    uint32_t maxmem;
    uint32_t timeout;
    time_t nextupdate;
    struct cl_engine *engine;
#ifdef CL_THREAD_SAFE
    pthread_mutex_t mutex;
#endif
} cli_intel_t;

typedef struct {
    uint64_t v[2][4];
} icon_groupset;

struct icomtr {
    unsigned int group[2];
    unsigned int color_avg[3];
    unsigned int color_x[3];
    unsigned int color_y[3];
    unsigned int gray_avg[3];
    unsigned int gray_x[3];
    unsigned int gray_y[3];
    unsigned int bright_avg[3];
    unsigned int bright_x[3];
    unsigned int bright_y[3];
    unsigned int dark_avg[3];
    unsigned int dark_x[3];
    unsigned int dark_y[3];
    unsigned int edge_avg[3];
    unsigned int edge_x[3];
    unsigned int edge_y[3];
    unsigned int noedge_avg[3];
    unsigned int noedge_x[3];
    unsigned int noedge_y[3];
    unsigned int rsum;
    unsigned int gsum;
    unsigned int bsum;
    unsigned int ccount;
    char *name;
};

struct icon_matcher {
    char **group_names[2];
    uint32_t group_counts[2];
    struct icomtr *icons[3];
    uint32_t icon_counts[3];
};

struct cli_dbinfo {
    char *name;
    char *hash;
    size_t size;
    struct cl_cvd *cvd;
    struct cli_dbinfo *next;
};

#define CLI_PWDB_COUNT 3
typedef enum {
    CLI_PWDB_ANY = 0,
    CLI_PWDB_ZIP = 1,
    CLI_PWDB_RAR = 2
} cl_pwdb_t;

struct cli_pwdb {
    char *name;
    char *passwd;
    uint16_t length;
    struct cli_pwdb *next;
};

struct cl_engine {
    uint32_t refcount; /* reference counter */
    uint32_t sdb;
    uint32_t dboptions;
    uint32_t dbversion[2];
    uint32_t ac_only;
    uint32_t ac_mindepth;
    uint32_t ac_maxdepth;
    char *tmpdir;
    char *certs_directory;
    uint32_t keeptmp;
    uint64_t engine_options;
    uint32_t cache_size;

    /* Limits */
    uint32_t maxscantime;         /* Time limit (in milliseconds) */
    uint64_t maxscansize;         /* during the scanning of archives this size
                                   * will never be exceeded
                                   */
    uint64_t maxfilesize;         /* compressed files will only be decompressed
                                   * and scanned up to this size
                                   */
    uint32_t max_recursion_level; /* maximum recursion level for archives */
    uint32_t maxfiles;            /* maximum number of files to be scanned
                                   * within a single archive
                                   */
    /* This is for structured data detection.  You can set the minimum
     * number of occurrences of an CC# or SSN before the system will
     * generate a notification.
     */
    uint32_t min_cc_count;
    uint32_t min_ssn_count;

    /* Roots table */
    struct cli_matcher **root;

    /* hash matcher for standard MD5 sigs */
    struct cli_matcher *hm_hdb;
    /* hash matcher for MD5 sigs for PE sections */
    struct cli_matcher *hm_mdb;
    /* hash matcher for MD5 sigs for PE import tables */
    struct cli_matcher *hm_imp;
    /* hash matcher for allow list db */
    struct cli_matcher *hm_fp;

    /* Container metadata */
    struct cli_cdb *cdb;

    /* Phishing .pdb and .wdb databases*/
    struct regex_matcher *allow_list_matcher;
    struct regex_matcher *domain_list_matcher;
    struct phishcheck *phishcheck;

    /* Dynamic configuration */
    struct cli_dconf *dconf;

    /* Filetype definitions */
    struct cli_ftype *ftypes;
    struct cli_ftype *ptypes;

    /* Container password storage */
    struct cli_pwdb **pwdbs;

    /* Pre-loading test matcher
     * Test for presence before using; cleared on engine compile.
     */
    struct cli_matcher *test_root;

    /* Ignored signatures */
    struct cli_matcher *ignored;

    /* PUA categories (to be included or excluded) */
    char *pua_cats;

    /* Icon reference storage */
    struct icon_matcher *iconcheck;

    /* Negative cache storage */
    struct CACHE *cache;

    /* Database information from .info files */
    struct cli_dbinfo *dbinfo;

    /* Signature counting, for progress callbacks */
    size_t num_total_signatures;

    /* Used for memory pools */
    mpool_t *mempool;

    /* crtmgr stuff */
    crtmgr cmgr;

    /* Callback(s) */
    clcb_scan cb_scan_pre_hash;
    clcb_scan cb_scan_pre_scan;
    clcb_scan cb_scan_post_scan;
    clcb_scan cb_scan_alert;
    clcb_scan cb_scan_file_type;
    clcb_pre_cache cb_pre_cache;
    clcb_file_inspection cb_file_inspection;
    clcb_pre_scan cb_pre_scan;
    clcb_post_scan cb_post_scan;
    clcb_virus_found cb_virus_found;
    clcb_sigload cb_sigload;
    void *cb_sigload_ctx;
    clcb_hash cb_hash;
    clcb_meta cb_meta;
    clcb_generic_data cb_vba;
    clcb_file_props cb_file_props;
    clcb_progress cb_sigload_progress;
    void *cb_sigload_progress_ctx;
    clcb_progress cb_engine_compile_progress;
    void *cb_engine_compile_progress_ctx;
    clcb_progress cb_engine_free_progress;
    void *cb_engine_free_progress_ctx;

    /* Used for bytecode */
    struct cli_all_bc bcs;
    unsigned *hooks[_BC_LAST_HOOK - _BC_START_HOOKS];
    unsigned hooks_cnt[_BC_LAST_HOOK - _BC_START_HOOKS];
    unsigned hook_lsig_ids;
    enum bytecode_security bytecode_security;
    uint32_t bytecode_timeout;
    enum bytecode_mode bytecode_mode;

    /* Engine max settings */
    uint64_t maxembeddedpe;      /* max size to scan MSEXE for PE */
    uint64_t maxhtmlnormalize;   /* max size to normalize HTML */
    uint64_t maxhtmlnotags;      /* max size for scanning normalized HTML */
    uint64_t maxscriptnormalize; /* max size to normalize scripts */
    uint64_t maxziptypercg;      /* max size to re-do zip filetype */

    /* Statistics/intelligence gathering */
    void *stats_data;
    clcb_stats_add_sample cb_stats_add_sample;
    clcb_stats_remove_sample cb_stats_remove_sample;
    clcb_stats_decrement_count cb_stats_decrement_count;
    clcb_stats_submit cb_stats_submit;
    clcb_stats_flush cb_stats_flush;
    clcb_stats_get_num cb_stats_get_num;
    clcb_stats_get_size cb_stats_get_size;
    clcb_stats_get_hostid cb_stats_get_hostid;

    /* Raw disk image max settings */
    uint32_t maxpartitions; /* max number of partitions to scan in a disk image */

    /* Engine max settings */
    uint32_t maxiconspe; /* max number of icons to scan for PE */
    uint32_t maxrechwp3; /* max recursive calls for HWP3 parsing */

    /* PCRE matching limitations */
    uint64_t pcre_match_limit;
    uint64_t pcre_recmatch_limit;
    uint64_t pcre_max_filesize;

#ifdef HAVE_YARA
    /* YARA */
    struct _yara_global *yara_global;
#endif
};

struct cl_settings {
    /* don't store dboptions here; it needs to be provided to cl_load() and
     * can be optionally obtained with cl_engine_get() or from the original
     * settings stored by the application
     */
    uint32_t ac_only;
    uint32_t ac_mindepth;
    uint32_t ac_maxdepth;
    char *tmpdir;
    uint32_t keeptmp;
    uint32_t maxscantime;
    uint64_t maxscansize;
    uint64_t maxfilesize;
    uint32_t max_recursion_level;
    uint32_t maxfiles;
    uint32_t min_cc_count;
    uint32_t min_ssn_count;
    enum bytecode_security bytecode_security;
    uint32_t bytecode_timeout;
    enum bytecode_mode bytecode_mode;
    char *pua_cats;
    uint64_t engine_options;
    uint32_t cache_size;

    /* callbacks */
    clcb_pre_cache cb_pre_cache;
    clcb_pre_scan cb_pre_scan;
    clcb_post_scan cb_post_scan;
    clcb_virus_found cb_virus_found;
    clcb_sigload cb_sigload;
    void *cb_sigload_ctx;
    clcb_msg cb_msg;
    clcb_hash cb_hash;
    clcb_meta cb_meta;
    clcb_file_props cb_file_props;
    clcb_progress cb_sigload_progress;
    void *cb_sigload_progress_ctx;
    clcb_progress cb_engine_compile_progress;
    void *cb_engine_compile_progress_ctx;
    clcb_progress cb_engine_free_progress;
    void *cb_engine_free_progress_ctx;

    /* Engine max settings */
    uint64_t maxembeddedpe;      /* max size to scan MSEXE for PE */
    uint64_t maxhtmlnormalize;   /* max size to normalize HTML */
    uint64_t maxhtmlnotags;      /* max size for scanning normalized HTML */
    uint64_t maxscriptnormalize; /* max size to normalize scripts */
    uint64_t maxziptypercg;      /* max size to re-do zip filetype */

    /* Statistics/intelligence gathering */
    void *stats_data;
    clcb_stats_add_sample cb_stats_add_sample;
    clcb_stats_remove_sample cb_stats_remove_sample;
    clcb_stats_decrement_count cb_stats_decrement_count;
    clcb_stats_submit cb_stats_submit;
    clcb_stats_flush cb_stats_flush;
    clcb_stats_get_num cb_stats_get_num;
    clcb_stats_get_size cb_stats_get_size;
    clcb_stats_get_hostid cb_stats_get_hostid;

    /* Raw disk image max settings */
    uint32_t maxpartitions; /* max number of partitions to scan in a disk image */

    /* Engine max settings */
    uint32_t maxiconspe; /* max number of icons to scan for PE */
    uint32_t maxrechwp3; /* max recursive calls for HWP3 parsing */

    /* PCRE matching limitations */
    uint64_t pcre_match_limit;
    uint64_t pcre_recmatch_limit;
    uint64_t pcre_max_filesize;
};

extern cl_unrar_error_t (*cli_unrar_open)(const char *filename, void **hArchive, char **comment, uint32_t *comment_size, uint8_t debug_flag);
extern cl_unrar_error_t (*cli_unrar_peek_file_header)(void *hArchive, unrar_metadata_t *file_metadata);
extern cl_unrar_error_t (*cli_unrar_extract_file)(void *hArchive, const char *destPath, char *outputBuffer);
extern cl_unrar_error_t (*cli_unrar_skip_file)(void *hArchive);
extern void (*cli_unrar_close)(void *hArchive);

extern LIBCLAMAV_EXPORT int have_rar;

#define SCAN_ALLMATCHES (ctx->options->general & CL_SCAN_GENERAL_ALLMATCHES)
#define SCAN_COLLECT_METADATA (ctx->options->general & CL_SCAN_GENERAL_COLLECT_METADATA)
#define SCAN_HEURISTICS (ctx->options->general & CL_SCAN_GENERAL_HEURISTICS)
#define SCAN_HEURISTIC_PRECEDENCE (ctx->options->general & CL_SCAN_GENERAL_HEURISTIC_PRECEDENCE)
#define SCAN_UNPRIVILEGED (ctx->options->general & CL_SCAN_GENERAL_UNPRIVILEGED)
#define SCAN_STORE_HTML_URIS (ctx->options->general & CL_SCAN_GENERAL_STORE_HTML_URIS)
#define SCAN_STORE_PDF_URIS (ctx->options->general & CL_SCAN_GENERAL_STORE_PDF_URIS)
#define SCAN_STORE_EXTRA_HASHES (ctx->options->general & CL_SCAN_GENERAL_STORE_EXTRA_HASHES)

#define SCAN_PARSE_ARCHIVE (ctx->options->parse & CL_SCAN_PARSE_ARCHIVE)
#define SCAN_PARSE_ELF (ctx->options->parse & CL_SCAN_PARSE_ELF)
#define SCAN_PARSE_PDF (ctx->options->parse & CL_SCAN_PARSE_PDF)
#define SCAN_PARSE_SWF (ctx->options->parse & CL_SCAN_PARSE_SWF)
#define SCAN_PARSE_HWP3 (ctx->options->parse & CL_SCAN_PARSE_HWP3)
#define SCAN_PARSE_XMLDOCS (ctx->options->parse & CL_SCAN_PARSE_XMLDOCS)
#define SCAN_PARSE_MAIL (ctx->options->parse & CL_SCAN_PARSE_MAIL)
#define SCAN_PARSE_OLE2 (ctx->options->parse & CL_SCAN_PARSE_OLE2)
#define SCAN_PARSE_HTML (ctx->options->parse & CL_SCAN_PARSE_HTML)
#define SCAN_PARSE_PE (ctx->options->parse & CL_SCAN_PARSE_PE)
#define SCAN_PARSE_ONENOTE (ctx->options->parse & CL_SCAN_PARSE_ONENOTE)
#define SCAN_PARSE_IMAGE (ctx->options->parse & CL_SCAN_PARSE_IMAGE)
#define SCAN_PARSE_IMAGE_FUZZY_HASH (ctx->options->parse & CL_SCAN_PARSE_IMAGE_FUZZY_HASH)

#define SCAN_HEURISTIC_BROKEN (ctx->options->heuristic & CL_SCAN_HEURISTIC_BROKEN)
#define SCAN_HEURISTIC_BROKEN_MEDIA (ctx->options->heuristic & CL_SCAN_HEURISTIC_BROKEN_MEDIA)
#define SCAN_HEURISTIC_EXCEEDS_MAX (ctx->options->heuristic & CL_SCAN_HEURISTIC_EXCEEDS_MAX)
#define SCAN_HEURISTIC_PHISHING_SSL_MISMATCH (ctx->options->heuristic & CL_SCAN_HEURISTIC_PHISHING_SSL_MISMATCH)
#define SCAN_HEURISTIC_PHISHING_CLOAK (ctx->options->heuristic & CL_SCAN_HEURISTIC_PHISHING_CLOAK)
#define SCAN_HEURISTIC_MACROS (ctx->options->heuristic & CL_SCAN_HEURISTIC_MACROS)
#define SCAN_HEURISTIC_ENCRYPTED_ARCHIVE (ctx->options->heuristic & CL_SCAN_HEURISTIC_ENCRYPTED_ARCHIVE)
#define SCAN_HEURISTIC_ENCRYPTED_DOC (ctx->options->heuristic & CL_SCAN_HEURISTIC_ENCRYPTED_DOC)
#define SCAN_HEURISTIC_PARTITION_INTXN (ctx->options->heuristic & CL_SCAN_HEURISTIC_PARTITION_INTXN)
#define SCAN_HEURISTIC_STRUCTURED (ctx->options->heuristic & CL_SCAN_HEURISTIC_STRUCTURED)
#define SCAN_HEURISTIC_STRUCTURED_SSN_NORMAL (ctx->options->heuristic & CL_SCAN_HEURISTIC_STRUCTURED_SSN_NORMAL)
#define SCAN_HEURISTIC_STRUCTURED_SSN_STRIPPED (ctx->options->heuristic & CL_SCAN_HEURISTIC_STRUCTURED_SSN_STRIPPED)

#define SCAN_MAIL_PARTIAL_MESSAGE (ctx->options->mail & CL_SCAN_MAIL_PARTIAL_MESSAGE)

#define SCAN_DEV_COLLECT_PERF_INFO (ctx->options->dev & CL_SCAN_DEV_COLLECT_PERFORMANCE_INFO)

/* based on macros from A. Melnikoff */
#define cbswap16(v) (((v & 0xff) << 8) | (((v) >> 8) & 0xff))
#define cbswap32(v) ((((v) & 0x000000ff) << 24) | (((v) & 0x0000ff00) << 8) | \
                     (((v) & 0x00ff0000) >> 8) | (((v) & 0xff000000) >> 24))
#define cbswap64(v) ((((v) & 0x00000000000000ffULL) << 56) | \
                     (((v) & 0x000000000000ff00ULL) << 40) | \
                     (((v) & 0x0000000000ff0000ULL) << 24) | \
                     (((v) & 0x00000000ff000000ULL) << 8) |  \
                     (((v) & 0x000000ff00000000ULL) >> 8) |  \
                     (((v) & 0x0000ff0000000000ULL) >> 24) | \
                     (((v) & 0x00ff000000000000ULL) >> 40) | \
                     (((v) & 0xff00000000000000ULL) >> 56))

#ifndef HAVE_ATTRIB_PACKED
#define __attribute__(x)
#endif
#ifdef HAVE_PRAGMA_PACK
#pragma pack(1)
#endif
#ifdef HAVE_PRAGMA_PACK_HPPA
#pragma pack 1
#endif

union unaligned_64 {
    uint64_t una_u64;
    int64_t una_s64;
} __attribute__((packed));

union unaligned_32 {
    uint32_t una_u32;
    int32_t una_s32;
} __attribute__((packed));

union unaligned_16 {
    uint16_t una_u16;
    int16_t una_s16;
} __attribute__((packed));

struct unaligned_ptr {
    void *ptr;
} __attribute__((packed));

#ifdef HAVE_PRAGMA_PACK
#pragma pack()
#endif
#ifdef HAVE_PRAGMA_PACK_HPPA
#pragma pack
#endif

#if WORDS_BIGENDIAN == 0
/* Little endian */
#define le16_to_host(v) (v)
#define le32_to_host(v) (v)
#define le64_to_host(v) (v)
#define be16_to_host(v) cbswap16(v)
#define be32_to_host(v) cbswap32(v)
#define be64_to_host(v) cbswap64(v)
#define cli_readint64(buff) (((const union unaligned_64 *)(buff))->una_s64)
#define cli_readint32(buff) (((const union unaligned_32 *)(buff))->una_s32)
#define cli_readint16(buff) (((const union unaligned_16 *)(buff))->una_s16)
#define cli_writeint32(offset, value) (((union unaligned_32 *)(offset))->una_u32 = (uint32_t)(value))
#else
/* Big endian */
#define le16_to_host(v) cbswap16(v)
#define le32_to_host(v) cbswap32(v)
#define le64_to_host(v) cbswap64(v)
#define be16_to_host(v) (v)
#define be32_to_host(v) (v)
#define be64_to_host(v) (v)

static inline int64_t cli_readint64(const void *buff)
{
    int64_t ret;
    ret = (int64_t)((const char *)buff)[0] & 0xff;
    ret |= (int64_t)(((const char *)buff)[1] & 0xff) << 8;
    ret |= (int64_t)(((const char *)buff)[2] & 0xff) << 16;
    ret |= (int64_t)(((const char *)buff)[3] & 0xff) << 24;

    ret |= (int64_t)(((const char *)buff)[4] & 0xff) << 32;
    ret |= (int64_t)(((const char *)buff)[5] & 0xff) << 40;
    ret |= (int64_t)(((const char *)buff)[6] & 0xff) << 48;
    ret |= (int64_t)(((const char *)buff)[7] & 0xff) << 56;
    return ret;
}

static inline int32_t cli_readint32(const void *buff)
{
    int32_t ret;
    ret = (int32_t)((const char *)buff)[0] & 0xff;
    ret |= (int32_t)(((const char *)buff)[1] & 0xff) << 8;
    ret |= (int32_t)(((const char *)buff)[2] & 0xff) << 16;
    ret |= (int32_t)(((const char *)buff)[3] & 0xff) << 24;
    return ret;
}

static inline int16_t cli_readint16(const void *buff)
{
    int16_t ret;
    ret = (int16_t)((const char *)buff)[0] & 0xff;
    ret |= (int16_t)(((const char *)buff)[1] & 0xff) << 8;
    return ret;
}

static inline void cli_writeint32(void *offset, uint32_t value)
{
    ((char *)offset)[0] = value & 0xff;
    ((char *)offset)[1] = (value & 0xff00) >> 8;
    ((char *)offset)[2] = (value & 0xff0000) >> 16;
    ((char *)offset)[3] = (value & 0xff000000) >> 24;
}
#endif

/**
 * @brief Append an alert.
 *
 * An FP-check will verify that the file is not allowed.
 * The allow list check does not happen before the scan because allowing files
 * is so infrequent that such action would be detrimental to performance.
 *
 * TODO: Replace implementation with severity scale, and severity threshold
 * wherein signatures that do not meet the threshold are documented in JSON
 * metadata but do not halt the scan.
 *
 * @param ctx       The scan context.
 * @param virname   The alert name.
 * @return cl_error_t CL_VIRUS if scan should be halted due to an alert, CL_CLEAN if scan should continue.
 */
cl_error_t cli_append_virus(cli_ctx *ctx, const char *virname);

/**
 * @brief Append a PUA (low severity) alert.
 *
 * This function will return CLEAN unless in all-match or Heuristic-precedence
 * modes. The intention is for the scan to continue in case something more
 * malicious is found.
 *
 * TODO: Replace implementation with severity scale, and severity threshold
 * wherein signatures that do not meet the threshold are documented in JSON
 * metadata but do not halt the scan.
 *
 * BUG: In normal scan mode (see above), the alert is not FP-checked!
 *
 * @param ctx       The scan context.
 * @param virname   The alert name.
 * @return cl_error_t CL_VIRUS if scan should be halted due to an alert, CL_CLEAN if scan should continue.
 */
cl_error_t cli_append_potentially_unwanted(cli_ctx *ctx, const char *virname);

/**
 * @brief If the SCAN_HEURISTIC_EXCEEDS_MAX option is enabled, append a "potentially unwanted" indicator.
 *
 * There is no return value because the caller should select the appropriate "CL_EMAX*" error code regardless
 * of whether or not an FP sig is found, or allmatch is enabled, or whatever.
 * That is, the scan must not continue because of an FP sig.
 *
 * @param ctx       The scan context.
 * @param virname   The name of the potentially unwanted indicator.
 */
void cli_append_potentially_unwanted_if_heur_exceedsmax(cli_ctx *ctx, char *virname);

const char *cli_get_last_virus(const cli_ctx *ctx);
const char *cli_get_last_virus_str(const cli_ctx *ctx);

/**
 * @brief Dispatch the alert / virus found callbacks.
 *
 * AKA for clamscan it will print FOUND message.
 *
 * @param ctx                     The scan context.
 * @param virname                 The name of the virus.
 * @param is_potentially_unwanted true if the alert is for a potentially unwanted application (PUA).
 * @return cl_error_t
 */
cl_error_t cli_virus_found_cb(cli_ctx *ctx, const char *virname, bool is_potentially_unwanted);

/**
 * @brief Push a new fmap onto our scan recursion stack.
 *
 * May fail if we exceed max recursion depth.
 *
 * @param ctx           The scanning context.
 * @param map           The fmap for the new layer.
 * @param type          The file type. May be CL_TYPE_ANY if unknown. Can change it later with cli_recursion_stack_change_type().
 * @param is_new_buffer true if the fmap represents a new buffer/file, and not some window into an existing fmap.
 * @param attributes    Layer attributes for the thing to be scanned.
 * @return cl_error_t   CL_SUCCESS if successful, else CL_EMAXREC if exceeding the max recursion depth.
 */
cl_error_t cli_recursion_stack_push(cli_ctx *ctx, cl_fmap_t *map, cli_file_t type, bool is_new_buffer, uint32_t attributes);

/**
 * @brief Pop off a layer of our scan recursion stack.
 *
 * Returns the fmap for the popped layer. Does NOT fmap_free() the fmap for you.
 *
 * @param ctx           The scanning context.
 * @return cl_fmap_t*   A pointer to the fmap for the popped layer, may return NULL instead if the stack is empty.
 */
cl_fmap_t *cli_recursion_stack_pop(cli_ctx *ctx);

/**
 * @brief Re-assign the type for the current layer.
 *
 * @param ctx           The scanning context.
 * @param type          The new file type.
 * @param run_callback  Whether to run the scan callback for file type corrections.
 *
 * @return cl_error_t   CL_SUCCESS if successful, else an error code.
 */
cl_error_t cli_recursion_stack_change_type(cli_ctx *ctx, cli_file_t type, bool run_callback);

/**
 * @brief Get the type of a specific layer.
 *
 * Ignores normalized layers internally.
 *
 * For index:
 *  0 == the outermost (bottom) layer of the stack.
 *  1 == the first layer (probably never explicitly used).
 * -1 == the present innermost (top) layer of the stack.
 * -2 == the parent layer (or "container"). That is, the second from the top of the stack.
 *
 * @param ctx           The scanning context.
 * @param index         Desired index, will be converted internally as though the normalized layers were stripped out. Don't think too had about it. Or do. ¯\_(ツ)_/¯
 * @return cli_file_t   The type of the requested layer,
 *                      or returns CL_TYPE_ANY if a negative layer is requested,
 *                      or returns CL_TYPE_IGNORED if requested layer too high.
 */
cli_file_t cli_recursion_stack_get_type(cli_ctx *ctx, int index);

/**
 * @brief Get the size of a specific layer.
 *
 * Ignores normalized layers internally.
 *
 * For index:
 *  0 == the outermost (bottom) layer of the stack.
 *  1 == the first layer (probably never explicitly used).
 * -1 == the present innermost (top) layer of the stack.
 * -2 == the parent layer (or "container"). That is, the second from the top of the stack.
 *
 * @param ctx           The scanning context.
 * @param index         Desired index, will be converted internally as though the normalized layers were stripped out. Don't think too had about it. Or do. ¯\_(ツ)_/¯
 * @return cli_file_t   The size of the requested layer,
 *                      or returns the size of the whole file if a negative layer is requested,
 *                      or returns 0 if requested layer too high.
 */
size_t cli_recursion_stack_get_size(cli_ctx *ctx, int index);

/**
 * @brief Dispatch scan callback based on location.
 *
 * @param ctx           Current scan context.
 * @param location      Callback location.
 * @return cl_error_t
 */
cl_error_t cli_dispatch_scan_callback(cli_ctx *ctx, cl_scan_callback_t location);

/* used by: spin, yc (C) aCaB */
#define __SHIFTBITS(a) (sizeof(a) << 3)
#define __SHIFTMASK(a) (__SHIFTBITS(a) - 1)
#define CLI_ROL(a, b) a = (a << ((b) & __SHIFTMASK(a))) | (a >> ((__SHIFTBITS(a) - (b)) & __SHIFTMASK(a)))
#define CLI_ROR(a, b) a = (a >> ((b) & __SHIFTMASK(a))) | (a << ((__SHIFTBITS(a) - (b)) & __SHIFTMASK(a)))

/* Implementation independent sign-extended signed right shift */
#ifdef HAVE_SAR
#define CLI_SRS(n, s) ((n) >> (s))
#else
#define CLI_SRS(n, s) ((((n) >> (s)) ^ (1 << (sizeof(n) * 8 - 1 - s))) - (1 << (sizeof(n) * 8 - 1 - s)))
#endif
#define CLI_SAR(n, s) n = CLI_SRS(n, s)

#ifdef __GNUC__
void cli_warnmsg(const char *str, ...) __attribute__((format(printf, 1, 2)));
#else
void cli_warnmsg(const char *str, ...);
#endif

#ifdef __GNUC__
void cli_errmsg(const char *str, ...) __attribute__((format(printf, 1, 2)));
#else
void cli_errmsg(const char *str, ...);
#endif

#ifdef __GNUC__
void cli_infomsg(const cli_ctx *ctx, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
#else
void cli_infomsg(const cli_ctx *ctx, const char *fmt, ...);
#endif

#ifdef __GNUC__
void cli_infomsg_simple(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
#else
void cli_infomsg_simple(const char *fmt, ...);
#endif

void cli_logg_setup(const cli_ctx *ctx);
void cli_logg_unsetup(void);

/* tell compiler about branches that are very rarely taken,
 * such as debug paths, and error paths */
#if (__GNUC__ >= 4) || (__GNUC__ == 3 && __GNUC_MINOR__ >= 2)
#define UNLIKELY(cond) __builtin_expect(!!(cond), 0)
#define LIKELY(cond) __builtin_expect(!!(cond), 1)
#else
#define UNLIKELY(cond) (cond)
#define LIKELY(cond) (cond)
#endif

#ifdef __GNUC__
#define always_inline inline __attribute__((always_inline))
#define never_inline __attribute__((noinline))
#else
#define never_inline
#define always_inline inline
#endif

#if defined(__GNUC__) && ((__GNUC__ > 4) || (__GNUC__ == 4 && __GNUC_MINOR__ >= 3))
#define __hot__ __attribute__((hot))
#else
#define __hot__
#endif

#ifdef __GNUC__
inline void cli_dbgmsg(const char *str, ...) __attribute__((format(printf, 1, 2)));
#else
inline void cli_dbgmsg(const char *str, ...);
#endif

#ifdef __GNUC__
void cli_dbgmsg_no_inline(const char *str, ...) __attribute__((format(printf, 1, 2)));
#else
void cli_dbgmsg_no_inline(const char *str, ...);
#endif

#ifdef __GNUC__
size_t cli_eprintf(const char *str, ...) __attribute__((format(printf, 1, 2)));
#else
size_t cli_eprintf(const char *str, ...);
#endif

#ifdef HAVE_CLI_GETPAGESIZE
#undef HAVE_CLI_GETPAGESIZE
#endif

#ifdef _WIN32
static inline int cli_getpagesize(void)
{
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return si.dwPageSize;
}
#define HAVE_CLI_GETPAGESIZE 1
#else /* ! _WIN32 */
#if HAVE_SYSCONF_SC_PAGESIZE
static inline int cli_getpagesize(void)
{
    return sysconf(_SC_PAGESIZE);
}
#define HAVE_CLI_GETPAGESIZE 1
#else
#if HAVE_GETPAGESIZE
static inline int cli_getpagesize(void)
{
    return getpagesize();
}
#define HAVE_CLI_GETPAGESIZE 1
#endif /* HAVE_GETPAGESIZE */
#endif /* HAVE_SYSCONF_SC_PAGESIZE */
#endif /* _WIN32 */

/**
 * @brief Wrapper around malloc that limits how much may be allocated to CLI_MAX_ALLOCATION.
 *
 * Please use CLI_MAX_MALLOC_OR_GOTO_DONE() with `goto done;` error handling instead.
 *
 * @param ptr
 * @param size
 * @return void*
 */
void *cli_max_malloc(size_t nmemb);

/**
 * @brief Wrapper around calloc that limits how much may be allocated to CLI_MAX_ALLOCATION.
 *
 * Please use CLI_MAX_CALLOC_OR_GOTO_DONE() with `goto done;` error handling instead.
 *
 * @param ptr
 * @param size
 * @return void*
 */
void *cli_max_calloc(size_t nmemb, size_t size);

/**
 * @brief Wrapper around realloc that limits how much may be allocated to CLI_MAX_ALLOCATION.
 *
 * Please use CLI_MAX_REALLOC_OR_GOTO_DONE() with `goto done;` error handling instead.
 *
 * NOTE: cli_max_realloc() will NOT free ptr if size==0. It is safe to free ptr after `done:`.
 *
 * IMPORTANT: This differs from realloc() in that if size==0, it will NOT free the ptr.
 *
 * @param ptr
 * @param size
 * @return void*
 */
void *cli_max_realloc(void *ptr, size_t size);

/**
 * @brief Wrapper around realloc that limits how much may be allocated to CLI_MAX_ALLOCATION.
 *
 * Please use CLI_MAX_REALLOC_OR_GOTO_DONE() with `goto done;` error handling instead.
 *
 * IMPORTANT: This differs from realloc() in that if size==0, it will NOT free the ptr.
 *
 * WARNING: This differs from cli_max_realloc() in that it will free the ptr if the allocation fails.
 * If you're using `goto done;` error handling, this may result in a double-free!!
 *
 * @param ptr
 * @param size
 * @return void*
 */
void *cli_max_realloc_or_free(void *ptr, size_t size);

/**
 * @brief Wrapper around realloc that, unlike some variants of realloc, will not free the ptr if size==0.
 *
 * Please use CLI_MAX_REALLOC_OR_GOTO_DONE() with `goto done;` error handling instead.
 *
 * IMPORTANT: This differs from realloc() in that if size==0, it will NOT free the ptr.
 *
 * @param ptr
 * @param size
 * @return void*
 */
void *cli_safer_realloc(void *ptr, size_t size);

/**
 * @brief Wrapper around realloc that, unlike some variants of realloc, will not free the ptr if size==0.
 *
 * Please use CLI_SAFER_REALLOC_OR_GOTO_DONE() with `goto done;` error handling instead.
 *
 * IMPORTANT: This differs from realloc() in that if size==0, it will NOT free the ptr.
 *
 * WARNING: This differs from cli_safer_realloc() in that it will free the ptr if the allocation fails.
 * If you're using `goto done;` error handling, this may result in a double-free!!
 *
 * @param ptr
 * @param size
 * @return void*
 */
void *cli_safer_realloc_or_free(void *ptr, size_t size);

/**
 * @brief Wrapper around strdup that does a NULL check.
 *
 * Please use CLI_STRDUP_OR_GOTO_DONE() with `goto done;` error handling instead.
 *
 * @param s
 * @return char* Returns the allocated string or NULL if allocation failed. This includes if allocation fails because s==NULL.
 */
char *cli_safer_strdup(const char *s);

int cli_rmdirs(const char *dirname);

/**
 * @brief Calculate a hash of a stream.
 * @param fs        The file stream to read from.
 * @param[out] hash (Optional) The buffer to store the calculated raw binary hash.
 * @param type      The type of hash to calculate.
 * @return char*    Returns the allocated hash string or NULL if allocation failed.
 */
char *cli_hashstream(FILE *fs, uint8_t *hash, cli_hash_type_t type);

/**
 * @brief Calculate a hash of a file.
 *
 * @param filename  The file to read from.
 * @param[out] hash (Optional) The buffer to store the calculated raw binary hash.
 * @param type      The type of hash to calculate.
 * @return char*    Returns the allocated hash string or NULL if allocation failed.
 */
char *cli_hashfile(const char *filename, uint8_t *hash, cli_hash_type_t type);

/**
 * @brief unlink() with error checking
 *
 * @param pathname the file path to unlink
 * @return cl_error_t CL_SUCCESS if successful, CL_EUNLINK if unlink() failed
 */
cl_error_t cli_unlink(const char *pathname);

size_t cli_readn(int fd, void *buff, size_t count);
size_t cli_writen(int fd, const void *buff, size_t count);
const char *cli_gettmpdir(void);

/**
 * @brief Sanitize a relative path, so it cannot have a negative depth.
 *
 * Caller is responsible for freeing the sanitized filepath.
 * The optional sanitized_filebase output param is a pointer into the filepath,
 * if set, and does not need to be freed.
 *
 * @param filepath                  The filepath to sanitize
 * @param filepath_len              The length of the filepath
 * @param[out] sanitized_filebase   Pointer to the basename portion of the sanitized filepath. (optional)
 * @return char*
 */
char *cli_sanitize_filepath(const char *filepath, size_t filepath_len, char **sanitized_filebase);

/**
 * @brief Generate tempfile filename (no path) with a random MD5 hash.
 *
 * Caller is responsible for freeing the filename.
 *
 * @return char* filename or NULL.
 */
char *cli_genfname(const char *prefix);

/**
 * @brief Generate a full tempfile filepath with a provided the name.
 *
 * Caller is responsible for freeing the filename.
 * If the dir is not provided, the engine->tmpdir will be used.
 *
 * @param dir 	 Alternative directory. (optional)
 * @return char* filename or NULL.
 */
char *cli_newfilepath(const char *dir, const char *fname);

/**
 * @brief Generate a full tempfile filepath with a provided the name.
 *
 * Caller is responsible for freeing the filename.
 * If the dir is not provided, the engine->tmpdir will be used.
 *
 * @param dir        Alternative temp directory (optional).
 * @param fname  	 Filename for new file.
 * @param[out] name  Allocated filepath, must be freed by caller.
 * @param[out] fd    File descriptor of open temp file.
 */
cl_error_t cli_newfilepathfd(const char *dir, char *fname, char **name, int *fd);

/**
 * @brief Generate a full tempfile filepath with a random MD5 hash and prefix the name, if provided.
 *
 * Caller is responsible for freeing the filename.
 *
 * @param dir 	 Alternative temp directory. (optional)
 * @param prefix (Optional) Prefix for new file tempfile.
 * @return char* filename or NULL.
 */
char *cli_gentemp_with_prefix(const char *dir, const char *prefix);

/**
 * @brief Generate a full tempfile filepath with a random MD5 hash.
 *
 * Caller is responsible for freeing the filename.
 *
 * @param dir 	 Alternative temp directory. (optional)
 * @return char* filename or NULL.
 */
char *cli_gentemp(const char *dir);

/**
 * @brief Create a temp filename, create the file, open it, and pass back the filepath and open file descriptor.
 *
 * @param dir        Alternative temp directory (optional).
 * @param[out] name  Allocated filepath, must be freed by caller.
 * @param[out] fd    File descriptor of open temp file.
 * @return cl_error_t CL_SUCCESS, CL_ECREAT, or CL_EMEM.
 */
cl_error_t cli_gentempfd(const char *dir, char **name, int *fd);

/**
 * @brief Create a temp filename, create the file, open it, and pass back the filepath and open file descriptor.
 *
 * @param dir        Alternative temp directory (optional).
 * @param prefix  	 (Optional) Prefix for new file tempfile.
 * @param[out] name  Allocated filepath, must be freed by caller.
 * @param[out] fd    File descriptor of open temp file.
 * @return cl_error_t CL_SUCCESS, CL_ECREAT, or CL_EMEM.
 */
cl_error_t cli_gentempfd_with_prefix(const char *dir, const char *prefix, char **name, int *fd);

unsigned int cli_rndnum(unsigned int max);
int cli_filecopy(const char *src, const char *dest);
bitset_t *cli_bitset_init(void);
void cli_bitset_free(bitset_t *bs);
int cli_bitset_set(bitset_t *bs, unsigned long bit_offset);
int cli_bitset_test(bitset_t *bs, unsigned long bit_offset);
const char *cli_ctime(const time_t *timep, char *buf, const size_t bufsize);

cl_error_t cli_checklimits(const char *who, cli_ctx *ctx, uint64_t need1, uint64_t need2, uint64_t need3);

/**
 * @brief Call before scanning a file to determine if we should scan it, skip it, or abort the entire scanning process.
 *
 * If the verdict is CL_SUCCESS, then this function increments the # of scanned files, and increments the amount of scanned data.
 * If the verdict is that a limit has been exceeded, then ctx->
 *
 * @param ctx       The scanning context.
 * @param needed    The size of the file we're considering scanning.
 * @return cl_error_t CL_SUCCESS if we're good to keep scanning else an error status.
 */
cl_error_t cli_updatelimits(cli_ctx *ctx, size_t needed);

int cli_matchregex(const char *str, const char *regex);
void cli_qsort(void *a, size_t n, size_t es, int (*cmp)(const void *, const void *));
void cli_qsort_r(void *a, size_t n, size_t es, int (*cmp)(const void *, const void *, const void *), void *arg);
cl_error_t cli_checktimelimit(cli_ctx *ctx);

/* symlink behaviour */
#define CLI_FTW_FOLLOW_FILE_SYMLINK 0x01
#define CLI_FTW_FOLLOW_DIR_SYMLINK 0x02

/* if the callback needs the stat */
#define CLI_FTW_NEED_STAT 0x04

/* remove leading/trailing slashes */
#define CLI_FTW_TRIM_SLASHES 0x08
#define CLI_FTW_STD (CLI_FTW_NEED_STAT | CLI_FTW_TRIM_SLASHES)

enum cli_ftw_reason {
    visit_file,
    visit_directory_toplev, /* this is a directory at toplevel of recursion */
    error_mem,              /* recommended to return CL_EMEM */
    /* recommended to return CL_SUCCESS below */
    error_stat,
    warning_skipped_link,
    warning_skipped_special,
    warning_skipped_dir
};

/* wrap void*, so that we don't mix it with some other pointer */
struct cli_ftw_cbdata {
    void *data;
};

/**
 * @brief Callback to process each file in a file tree walk (FTW).
 *
 * The callback is responsible for freeing filename when it is done using it.
 *
 * Note that callback decides if directory traversal should continue
 * after an error, we call the callback with reason == error,
 * and if it returns CL_BREAK we break.
 *
 * Return:
 * - CL_BREAK to break out without an error,
 * - CL_SUCCESS to continue,
 * - any CL_E* to break out due to error.
 */
typedef cl_error_t (*cli_ftw_cb)(STATBUF *stat_buf, char *filename, const char *path, enum cli_ftw_reason reason, struct cli_ftw_cbdata *data);

/**
 * @brief Callback to determine if a path in a file tree walk (FTW) should be skipped.
 * Has access to the same callback data as the main FTW callback function (above).
 *
 * Return:
 * - 1 if the path should be skipped (i.e. to not call the callback for the given path),
 * - 0 if the path should be processed (i.e. to call the callback for the given path).
 */
typedef int (*cli_ftw_pathchk)(const char *path, struct cli_ftw_cbdata *data);

/**
 * @brief Traverse a file path, calling the callback function on each file
 * within if the pathchk() check allows for it. Will skip certain file types:
 * -
 *
 * This is regardless of virus found/not, that is the callback's job to store.
 * Note that the callback may dispatch async the scan, so that when cli_ftw
 * returns we don't know the infected/notinfected status of the directory yet!
 *
 * Due to this if the callback scans synchronously it should store the infected
 * status in its cbdata.
 * This works for both files and directories. It stats the path to determine
 * which one it is.
 * If it is a file, it simply calls the callback once, otherwise recurses.
 *
 * @param base      The top level directory (or file) path to be processed
 * @param flags     A bitflag field for the CLI_FTW_* flag options (see above)
 * @param maxdepth  The max recursion depth.
 * @param callback  The cli_ftw_cb callback to invoke on each file AND directory.
 * @param data      Callback data for the callback function.
 * @param pathchk   A function used to determine if the callback should be run on the given file.
 * @return cl_error_t CL_SUCCESS if it traversed all files and subdirs
 * @return cl_error_t CL_BREAK if traversal has stopped at some point
 * @return cl_error_t CL_E* if error encountered during traversal and we had to break out
 */
cl_error_t cli_ftw(char *base, int flags, int maxdepth, cli_ftw_cb callback, struct cli_ftw_cbdata *data, cli_ftw_pathchk pathchk);

const char *cli_strerror(int errnum, char *buf, size_t len);

#ifdef _WIN32
/**
 * @brief   Attempt to get a filename from an open file handle.
 *
 * Windows only.
 *
 * @param hFile          File handle
 * @param[out] filepath  Will be set to file path if found, or NULL.
 * @return cl_error_t    CL_SUCCESS if found, else an error code.
 */
cl_error_t cli_get_filepath_from_handle(HANDLE hFile, char **filepath);
#endif

/**
 * @brief   Attempt to get a filename from an open file descriptor.
 *
 * Caller is responsible for free'ing the filename.
 * Should work on Linux, macOS, Windows.
 *
 * @param desc           File descriptor
 * @param[out] filepath  Will be set to file path if found, or NULL.
 * @return cl_error_t    CL_SUCCESS if found, else an error code.
 */
cl_error_t cli_get_filepath_from_filedesc(int desc, char **filepath);

/**
 * @brief   Attempt to get the real path of a provided path (evaluating symlinks).
 *
 * Caller is responsible for free'ing the file path.
 * On posix systems this just calls realpath() under the hood.
 * On Win32, it opens a handle and uses cli_get_filepath_from_filedesc()
 * to get the real path.
 *
 * @param desc          A file path to evaluate.
 * @param[out] char*    A malloced string containing the real path.
 * @return cl_error_t   CL_SUCCESS if found, else an error code.
 */
cl_error_t cli_realpath(const char *file_name, char **real_filename);

/**
 * @brief   Get the libclamav debug flag (e.g. if debug logging is enabled)
 *
 * This is required for unit tests to be able to link with clamav.dll and not
 * directly manipulate libclamav global variables.
 */
uint8_t cli_get_debug_flag(void);

/**
 * @brief   Set the libclamav debug flag to a specific value.
 *
 * The public cl_debug() API will only ever enable debug mode, it won't disable debug mode.
 *
 * This is required for unit tests to be able to link with clamav.dll and not
 * directly manipulate libclamav global variables.
 */
uint8_t cli_set_debug_flag(uint8_t debug_flag);

/**
 * @brief Trust the current layer by removing any evidence and setting the verdict to trusted.
 *
 * @param ctx           The scan context.
 * @param source        The source of the trust request.
 * @return cl_error_t   CL_SUCCESS on success, or an error code.
 */
cl_error_t cli_trust_this_layer(cli_ctx *ctx, const char *source);

/**
 * @brief Trust a range of layers by removing any evidence and setting the verdict to trusted.
 *
 * @param ctx           The scan context.
 * @param start_layer   The layer to start trusting from (inclusive).
 * @param end_layer     The layer to stop trusting at (inclusive).
 * @param source        The source of the trust request.
 * @return cl_error_t   CL_SUCCESS on success, or an error code.
 */
cl_error_t cli_trust_layers(cli_ctx *ctx, uint32_t start_layer, uint32_t end_layer, const char *source);

#ifndef CLI_SAFER_STRDUP_OR_GOTO_DONE
/**
 * @brief Wrapper around strdup that does a NULL check.
 *
 * This macro requires `goto done;` error handling.
 *
 * @param buf   The string to duplicate.
 * @param var   The variable to assign the allocated string to.
 * @param ...   The error handling code to execute if the allocation fails.
 */
#define CLI_SAFER_STRDUP_OR_GOTO_DONE(buf, var, ...) \
    do {                                             \
        var = cli_safer_strdup(buf);                 \
        if (NULL == var) {                           \
            do {                                     \
                __VA_ARGS__;                         \
            } while (0);                             \
            goto done;                               \
        }                                            \
    } while (0)
#endif

#ifndef CLI_FREE_AND_SET_NULL
/**
 * @brief Wrapper around `free()` to ensure you reset the variable to NULL so as to prevent a double-free.
 *
 * @param var The variable to free and set to NULL.
 */
#define CLI_FREE_AND_SET_NULL(var) \
    do {                           \
        if (NULL != var) {         \
            free((void *)var);     \
            var = NULL;            \
        }                          \
    } while (0)
#endif

#ifndef CLI_MALLOC_OR_GOTO_DONE
/**
 * @brief Wrapper around malloc that will `goto done;` if the allocation fails.
 *
 * This macro requires `goto done;` error handling.
 *
 * @param ptr   The variable to assign the allocated memory to.
 * @param size  The size of the memory to allocate.
 * @param ...   The error handling code to execute if the allocation fails.
 */
#define CLI_MALLOC_OR_GOTO_DONE(var, size, ...) \
    do {                                        \
        var = malloc(size);                     \
        if (NULL == var) {                      \
            do {                                \
                __VA_ARGS__;                    \
            } while (0);                        \
            goto done;                          \
        }                                       \
    } while (0)
#endif

#ifndef CLI_MAX_MALLOC_OR_GOTO_DONE
/**
 * @brief Wrapper around malloc that limits how much may be allocated to CLI_MAX_ALLOCATION.
 *
 * This macro requires `goto done;` error handling.
 *
 * @param var   The variable to assign the allocated memory to.
 * @param size  The size of the memory to allocate.
 * @param ...   The error handling code to execute if the allocation fails.
 */
#define CLI_MAX_MALLOC_OR_GOTO_DONE(var, size, ...) \
    do {                                            \
        var = cli_max_malloc(size);                 \
        if (NULL == var) {                          \
            do {                                    \
                __VA_ARGS__;                        \
            } while (0);                            \
            goto done;                              \
        }                                           \
    } while (0)
#endif

#ifndef CLI_CALLOC_OR_GOTO_DONE
/**
 * @brief Wrapper around calloc that will `goto done;` if the allocation fails.
 *
 * This macro requires `goto done;` error handling.
 *
 * @param var   The variable to assign the allocated memory to.
 * @param nmemb The number of elements to allocate.
 * @param size  The size of each element.
 * @param ...   The error handling code to execute if the allocation fails.
 */
#define CLI_CALLOC_OR_GOTO_DONE(var, nmemb, size, ...) \
    do {                                               \
        (var) = calloc(nmemb, size);                   \
        if (NULL == var) {                             \
            do {                                       \
                __VA_ARGS__;                           \
            } while (0);                               \
            goto done;                                 \
        }                                              \
    } while (0)
#endif

#ifndef CLI_MAX_CALLOC_OR_GOTO_DONE
/**
 * @brief Wrapper around calloc that limits how much may be allocated to CLI_MAX_ALLOCATION.
 *
 * This macro requires `goto done;` error handling.
 *
 * @param var   The variable to assign the allocated memory to.
 * @param nmemb The number of elements to allocate.
 * @param size  The size of each element.
 * @param ...   The error handling code to execute if the allocation fails.
 */
#define CLI_MAX_CALLOC_OR_GOTO_DONE(var, nmemb, size, ...) \
    do {                                                   \
        (var) = cli_max_calloc(nmemb, size);               \
        if (NULL == var) {                                 \
            do {                                           \
                __VA_ARGS__;                               \
            } while (0);                                   \
            goto done;                                     \
        }                                                  \
    } while (0)
#endif

#ifndef CLI_VERIFY_POINTER_OR_GOTO_DONE
/**
 * @brief Wrapper around a NULL-check that will `goto done;` if the pointer is NULL.
 *
 * This macro requires `goto done;` error handling.
 *
 * @param ptr   The pointer to verify.
 * @param ...   The error handling code to execute if the pointer is NULL.
 */
#define CLI_VERIFY_POINTER_OR_GOTO_DONE(ptr, ...) \
    do {                                          \
        if (NULL == ptr) {                        \
            do {                                  \
                __VA_ARGS__;                      \
            } while (0);                          \
            goto done;                            \
        }                                         \
    } while (0)
#endif

/**
 * @brief Wrapper around realloc that limits how much may be allocated to CLI_MAX_ALLOCATION.
 *
 * IMPORTANT: This differs from realloc() in that if size==0, it will NOT free the ptr.
 *
 * NOTE: cli_max_realloc() will NOT free ptr if size==0. It is safe to free ptr after `done:`.
 *
 * @param ptr   The pointer to realloc.
 * @param size  The size of the memory to allocate.
 * @param ...   The error handling code to execute if the allocation fails.
 */
#ifndef CLI_MAX_REALLOC_OR_GOTO_DONE
#define CLI_MAX_REALLOC_OR_GOTO_DONE(ptr, size, ...)     \
    do {                                                 \
        void *vTmp = cli_max_realloc((void *)ptr, size); \
        if (NULL == vTmp) {                              \
            do {                                         \
                __VA_ARGS__;                             \
            } while (0);                                 \
            goto done;                                   \
        }                                                \
        ptr = vTmp;                                      \
    } while (0)
#endif

/**
 * @brief Wrapper around realloc that, unlike some variants of realloc, will not free the ptr if size==0.
 *
 * IMPORTANT: This differs from realloc() in that if size==0, it will NOT free the ptr.
 *
 * NOTE: cli_safer_realloc() will NOT free ptr if size==0. It is safe to free ptr after `done:`.
 *
 * @param ptr   The pointer to realloc.
 * @param size  The size of the memory to allocate.
 * @param ...   The error handling code to execute if the allocation fails.
 */
#ifndef CLI_SAFER_REALLOC_OR_GOTO_DONE
#define CLI_SAFER_REALLOC_OR_GOTO_DONE(ptr, size, ...)     \
    do {                                                   \
        void *vTmp = cli_safer_realloc((void *)ptr, size); \
        if (NULL == vTmp) {                                \
            do {                                           \
                __VA_ARGS__;                               \
            } while (0);                                   \
            goto done;                                     \
        }                                                  \
        ptr = vTmp;                                        \
    } while (0)
#endif

#endif
