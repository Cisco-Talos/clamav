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
#include "cltypes.h"

#include "clamav.h"
#include "dconf.h"
#include "filetypes.h"
#include "fmap.h"
#include "libclamunrar_iface/unrar_iface.h"
#include "regex/regex.h"
#include "bytecode.h"
#include "bytecode_api.h"
#include "events.h"
#include "crtmgr.h"

/*
 * CL_FLEVEL is the signature f-level specific to the current code and
 *	     should never be modified
 * CL_FLEVEL_DCONF is used in the dconf module and can be bumped by
 * distribution packagers provided they fix *all* security issues found
 * in the old versions of ClamAV. Updating CL_FLEVEL_DCONF will result
 * in re-enabling affected modules.
 */

#define CL_FLEVEL 77
#define CL_FLEVEL_DCONF	CL_FLEVEL
#define CL_FLEVEL_SIGTOOL CL_FLEVEL

extern uint8_t cli_debug_flag;
extern uint8_t cli_always_gen_section_hash;

/*
 * CLI_ISCONTAINED(buf1, size1, buf2, size2) checks if buf2 is contained
 * within buf1.
 *
 * buf1 and buf2 are pointers (or offsets) for the main buffer and the
 * sub-buffer respectively, and size1/2 are their sizes
 *
 * The macro can be used to protect against wraps.
 */
#define CLI_ISCONTAINED(bb, bb_size, sb, sb_size)	\
  ((bb_size) > 0 && (sb_size) > 0 && (size_t)(sb_size) <= (size_t)(bb_size) \
   && (sb) >= (bb) && ((sb) + (sb_size)) <= ((bb) + (bb_size)) && ((sb) + (sb_size)) > (bb) && (sb) < ((bb) + (bb_size)))

#define CLI_ISCONTAINED2(bb, bb_size, sb, sb_size)	\
  ((bb_size) > 0 && (sb_size) >= 0 && (size_t)(sb_size) <= (size_t)(bb_size) \
   && (sb) >= (bb) && ((sb) + (sb_size)) <= ((bb) + (bb_size)) && ((sb) + (sb_size)) >= (bb) && (sb) < ((bb) + (bb_size)))

#define CLI_MAX_ALLOCATION (182*1024*1024)

#ifdef	HAVE_SYS_PARAM_H
#include <sys/param.h>	/* for NAME_MAX */
#endif

/* Maximum filenames under various systems - njh */
#ifndef	NAME_MAX	/* e.g. Linux */
# ifdef	MAXNAMELEN	/* e.g. Solaris */
#   define	NAME_MAX	MAXNAMELEN
# else
#   ifdef	FILENAME_MAX	/* e.g. SCO */
#     define	NAME_MAX	FILENAME_MAX
#   else
#     define    NAME_MAX        256
#   endif
# endif
#endif

#if NAME_MAX < 256
#undef NAME_MAX
#define NAME_MAX 256
#endif

typedef struct bitset_tag
{
        unsigned char *bitset;
        unsigned long length;
} bitset_t;

/* internal clamav context */
typedef struct cli_ctx_tag {
    const char **virname;
    unsigned int num_viruses;         /* manages virname when CL_SCAN_ALLMATCHES == 1 */
    unsigned int size_viruses;        /* manages virname when CL_SCAN_ALLMATCHES == 1 */
    unsigned long int *scanned;
    const struct cli_matcher *root;
    const struct cl_engine *engine;
    unsigned long scansize;
    unsigned int options;
    unsigned int recursion;
    unsigned int scannedfiles;
    unsigned int found_possibly_unwanted;
    unsigned int corrupted_input;
    unsigned int img_validate;
    cli_file_t container_type; /* FIXME: to be made into a stack or array - see bb#1579 & bb#1293 */
    size_t container_size;
    unsigned char handlertype_hash[16];
    struct cli_dconf *dconf;
    fmap_t **fmap;
    bitset_t* hook_lsig_matches;
    void *cb_ctx;
    cli_events_t* perf;
#ifdef HAVE__INTERNAL__SHA_COLLECT
    char entry_filename[2048];
    int sha_collect;
#endif
} cli_ctx;

#define STATS_ANON_UUID "5b585e8f-3be5-11e3-bf0b-18037319526c"
#define STATS_MAX_SAMPLES 50
#define STATS_MAX_MEM 1024*1024

typedef struct cli_flagged_sample {
    char **virus_name;
    char md5[16];
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

typedef struct {uint64_t v[2][4];} icon_groupset;

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
    unsigned int group_counts[2];
    struct icomtr *icons[3];
    unsigned int icon_counts[3];
};

struct cli_dbinfo {
    char *name;
    unsigned char *hash;
    size_t size;
    struct cl_cvd *cvd;
    struct cli_dbinfo *next;
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
    uint32_t keeptmp;
    uint64_t engine_options;

    /* Limits */
    uint64_t maxscansize;  /* during the scanning of archives this size
				     * will never be exceeded
				     */
    uint64_t maxfilesize;  /* compressed files will only be decompressed
				     * and scanned up to this size
				     */
    uint32_t maxreclevel;	    /* maximum recursion level for archives */
    uint32_t maxfiles;	    /* maximum number of files to be scanned
				     * within a single archive
				     */
    /* This is for structured data detection.  You can set the minimum
     * number of occurences of an CC# or SSN before the system will
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
    /* hash matcher for whitelist db */
    struct cli_matcher *hm_fp;


    /* Container metadata */
    struct cli_cdb *cdb;

    /* Phishing .pdb and .wdb databases*/
    struct regex_matcher *whitelist_matcher;
    struct regex_matcher *domainlist_matcher;
    struct phishcheck *phishcheck;

    /* Dynamic configuration */
    struct cli_dconf *dconf;

    /* Filetype definitions */
    struct cli_ftype *ftypes;
    struct cli_ftype *ptypes;

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

    /* Used for memory pools */
    mpool_t *mempool;

    /* crtmgr stuff */
    crtmgr cmgr;

    /* Callback(s) */
    clcb_pre_cache cb_pre_cache;
    clcb_pre_scan cb_pre_scan;
    clcb_post_scan cb_post_scan;
    clcb_sigload cb_sigload;
    void *cb_sigload_ctx;
    clcb_hash cb_hash;
    clcb_meta cb_meta;

    /* Used for bytecode */
    struct cli_all_bc bcs;
    unsigned *hooks[_BC_LAST_HOOK - _BC_START_HOOKS];
    unsigned hooks_cnt[_BC_LAST_HOOK - _BC_START_HOOKS];
    unsigned hook_lsig_ids;
    enum bytecode_security bytecode_security;
    uint32_t bytecode_timeout;
    enum bytecode_mode bytecode_mode;

    /* Engine max settings */
    uint64_t maxembeddedpe;  /* max size to scan MSEXE for PE */
    uint64_t maxhtmlnormalize; /* max size to normalize HTML */
    uint64_t maxhtmlnotags; /* max size for scanning normalized HTML */
    uint64_t maxscriptnormalize; /* max size to normalize scripts */
    uint64_t maxziptypercg; /* max size to re-do zip filetype */

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
    uint32_t maxpartitions;

    /* Engine max settings */
    uint32_t maxiconspe; /* max number of icons to scan for PE */
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
    uint64_t maxscansize;
    uint64_t maxfilesize;
    uint32_t maxreclevel;
    uint32_t maxfiles;
    uint32_t min_cc_count;
    uint32_t min_ssn_count;
    enum bytecode_security bytecode_security;
    uint32_t bytecode_timeout;
    enum bytecode_mode bytecode_mode;
    char *pua_cats;
    uint64_t engine_options;

    /* callbacks */
    clcb_pre_cache cb_pre_cache;
    clcb_pre_scan cb_pre_scan;
    clcb_post_scan cb_post_scan;
    clcb_sigload cb_sigload;
    void *cb_sigload_ctx;
    clcb_msg cb_msg;
    clcb_hash cb_hash;
    clcb_meta cb_meta;

    /* Engine max settings */
    uint64_t maxembeddedpe;  /* max size to scan MSEXE for PE */
    uint64_t maxhtmlnormalize; /* max size to normalize HTML */
    uint64_t maxhtmlnotags; /* max size for scanning normalized HTML */
    uint64_t maxscriptnormalize; /* max size to normalize scripts */
    uint64_t maxziptypercg; /* max size to re-do zip filetype */

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
};

extern int (*cli_unrar_open)(int fd, const char *dirname, unrar_state_t *state);
extern int (*cli_unrar_extract_next_prepare)(unrar_state_t *state, const char *dirname);
extern int (*cli_unrar_extract_next)(unrar_state_t *state, const char *dirname);
extern void (*cli_unrar_close)(unrar_state_t *state);
extern int have_rar;

#define SCAN_ARCHIVE	    (ctx->options & CL_SCAN_ARCHIVE)
#define SCAN_MAIL	    (ctx->options & CL_SCAN_MAIL)
#define SCAN_OLE2	    (ctx->options & CL_SCAN_OLE2)
#define SCAN_PDF	    (ctx->options & CL_SCAN_PDF)
#define SCAN_HTML	    (ctx->options & CL_SCAN_HTML)
#define SCAN_PE		    (ctx->options & CL_SCAN_PE)
#define SCAN_ELF	    (ctx->options & CL_SCAN_ELF)
#define SCAN_ALGO 	    (ctx->options & CL_SCAN_ALGORITHMIC)
#define DETECT_ENCRYPTED    (ctx->options & CL_SCAN_BLOCKENCRYPTED)
/* #define BLOCKMAX	    (ctx->options & CL_SCAN_BLOCKMAX) */
#define DETECT_BROKEN	    (ctx->options & CL_SCAN_BLOCKBROKEN)
#define BLOCK_MACROS	    (ctx->options & CL_SCAN_BLOCKMACROS)
#define SCAN_STRUCTURED	    (ctx->options & CL_SCAN_STRUCTURED)
#define SCAN_ALL            (ctx->options & CL_SCAN_ALLMATCHES)
#define SCAN_SWF            (ctx->options & CL_SCAN_SWF)

/* based on macros from A. Melnikoff */
#define cbswap16(v) (((v & 0xff) << 8) | (((v) >> 8) & 0xff))
#define cbswap32(v) ((((v) & 0x000000ff) << 24) | (((v) & 0x0000ff00) << 8) | \
		    (((v) & 0x00ff0000) >> 8)  | (((v) & 0xff000000) >> 24))
#define cbswap64(v) ((((v) & 0x00000000000000ffULL) << 56) | \
		     (((v) & 0x000000000000ff00ULL) << 40) | \
		     (((v) & 0x0000000000ff0000ULL) << 24) | \
		     (((v) & 0x00000000ff000000ULL) <<  8) | \
		     (((v) & 0x000000ff00000000ULL) >>  8) | \
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
#define le16_to_host(v)	(v)
#define le32_to_host(v)	(v)
#define le64_to_host(v)	(v)
#define	be16_to_host(v)	cbswap16(v)
#define	be32_to_host(v)	cbswap32(v)
#define be64_to_host(v) cbswap64(v)
#define cli_readint32(buff) (((const union unaligned_32 *)(buff))->una_s32)
#define cli_readint16(buff) (((const union unaligned_16 *)(buff))->una_s16)
#define cli_writeint32(offset, value) (((union unaligned_32 *)(offset))->una_u32=(uint32_t)(value))
#else
/* Big endian */
#define	le16_to_host(v)	cbswap16(v)
#define	le32_to_host(v)	cbswap32(v)
#define le64_to_host(v) cbswap64(v)
#define be16_to_host(v)	(v)
#define be32_to_host(v)	(v)
#define be64_to_host(v)	(v)

static inline int32_t cli_readint32(const char *buff)
{
	int32_t ret;
    ret = buff[0] & 0xff;
    ret |= (buff[1] & 0xff) << 8;
    ret |= (buff[2] & 0xff) << 16;
    ret |= (buff[3] & 0xff) << 24;
    return ret;
}

static inline int16_t cli_readint16(const char *buff)
{
	int16_t ret;
    ret = buff[0] & 0xff;
    ret |= (buff[1] & 0xff) << 8;
    return ret;
}

static inline void cli_writeint32(char *offset, uint32_t value)
{
    offset[0] = value & 0xff;
    offset[1] = (value & 0xff00) >> 8;
    offset[2] = (value & 0xff0000) >> 16;
    offset[3] = (value & 0xff000000) >> 24;
}
#endif

void cli_append_virus(cli_ctx *ctx, const char *virname);
const char *cli_get_last_virus(const cli_ctx *ctx);
const char *cli_get_last_virus_str(const cli_ctx *ctx);

/* used by: spin, yc (C) aCaB */
#define __SHIFTBITS(a) (sizeof(a)<<3)
#define __SHIFTMASK(a) (__SHIFTBITS(a)-1)
#define CLI_ROL(a,b) a = ( a << ((b) & __SHIFTMASK(a)) ) | ( a >> ((__SHIFTBITS(a) - (b)) & __SHIFTMASK(a)) )
#define CLI_ROR(a,b) a = ( a >> ((b) & __SHIFTMASK(a)) ) | ( a << ((__SHIFTBITS(a) - (b)) & __SHIFTMASK(a)) )

/* Implementation independent sign-extended signed right shift */
#ifdef HAVE_SAR
#define CLI_SRS(n,s) ((n)>>(s))
#else
#define CLI_SRS(n,s) ((((n)>>(s)) ^ (1<<(sizeof(n)*8-1-s))) - (1<<(sizeof(n)*8-1-s)))
#endif
#define CLI_SAR(n,s) n = CLI_SRS(n,s)

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
void cli_infomsg(const cli_ctx* ctx, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
#else
void cli_infomsg(const cli_ctx* ctx, const char *fmt, ...);
#endif

void cli_logg_setup(const cli_ctx* ctx);
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

#if defined (__GNUC__) && ((__GNUC__ > 4) || (__GNUC__ == 4 && __GNUC_MINOR__ >= 3))
#define __hot__ __attribute__((hot))
#else
#define __hot__
#endif

#define cli_dbgmsg (!UNLIKELY(cli_debug_flag)) ? (void)0 : cli_dbgmsg_internal

#ifdef __GNUC__
void cli_dbgmsg_internal(const char *str, ...) __attribute__((format(printf, 1, 2)));
#else
void cli_dbgmsg_internal(const char *str, ...);
#endif

#ifdef HAVE_CLI_GETPAGESIZE
#undef HAVE_CLI_GETPAGESIZE
#endif

#ifdef _WIN32
static inline int cli_getpagesize(void) {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return si.dwPageSize;
}
#else /* ! _WIN32 */
#if HAVE_SYSCONF_SC_PAGESIZE
static inline int cli_getpagesize(void) { return sysconf(_SC_PAGESIZE); }
#define HAVE_CLI_GETPAGESIZE 1
#else
#if HAVE_GETPAGESIZE
static inline int cli_getpagesize(void) { return getpagesize(); }
#define HAVE_CLI_GETPAGESIZE 1
#endif /* HAVE_GETPAGESIZE */
#endif /* HAVE_SYSCONF_SC_PAGESIZE */
#endif /* _WIN32 */

void *cli_malloc(size_t nmemb);
void *cli_calloc(size_t nmemb, size_t size);
void *cli_realloc(void *ptr, size_t size);
void *cli_realloc2(void *ptr, size_t size);
char *cli_strdup(const char *s);
int cli_rmdirs(const char *dirname);
char *cli_hashstream(FILE *fs, unsigned char *digcpy, int type);
char *cli_hashfile(const char *filename, int type);
int cli_unlink(const char *pathname);
int cli_readn(int fd, void *buff, unsigned int count);
int cli_writen(int fd, const void *buff, unsigned int count);
const char *cli_gettmpdir(void);
char *cli_gentemp(const char *dir);
int cli_gentempfd(const char *dir, char **name, int *fd);
unsigned int cli_rndnum(unsigned int max);
int cli_filecopy(const char *src, const char *dest);
int cli_mapscan(fmap_t *map, off_t offset, size_t size, cli_ctx *ctx, cli_file_t type);
bitset_t *cli_bitset_init(void);
void cli_bitset_free(bitset_t *bs);
int cli_bitset_set(bitset_t *bs, unsigned long bit_offset);
int cli_bitset_test(bitset_t *bs, unsigned long bit_offset);
const char* cli_ctime(const time_t *timep, char *buf, const size_t bufsize);
int cli_checklimits(const char *, cli_ctx *, unsigned long, unsigned long, unsigned long);
int cli_updatelimits(cli_ctx *, unsigned long);
unsigned long cli_getsizelimit(cli_ctx *, unsigned long);
int cli_matchregex(const char *str, const char *regex);
void cli_qsort(void *a, size_t n, size_t es, int (*cmp)(const void *, const void *));

/* symlink behaviour */
#define CLI_FTW_FOLLOW_FILE_SYMLINK 0x01
#define CLI_FTW_FOLLOW_DIR_SYMLINK  0x02

/* if the callback needs the stat */
#define CLI_FTW_NEED_STAT	    0x04

/* remove leading/trailing slashes */
#define CLI_FTW_TRIM_SLASHES	    0x08
#define CLI_FTW_STD (CLI_FTW_NEED_STAT | CLI_FTW_TRIM_SLASHES)

enum cli_ftw_reason {
    visit_file,
    visit_directory_toplev, /* this is a directory at toplevel of recursion */
    error_mem, /* recommended to return CL_EMEM */
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

/* 
 * return CL_BREAK to break out without an error, CL_SUCCESS to continue,
 * or any CL_E* to break out due to error.
 * The callback is responsible for freeing filename when it is done using it.
 * Note that callback decides if directory traversal should continue 
 * after an error, we call the callback with reason == error,
 * and if it returns CL_BREAK we break.
 */
typedef int (*cli_ftw_cb)(STATBUF *stat_buf, char *filename, const char *path, enum cli_ftw_reason reason, struct cli_ftw_cbdata *data);

/*
 * returns 1 if the path should be skipped and 0 otherwise
 * uses callback data
 */
typedef int (*cli_ftw_pathchk)(const char *path, struct cli_ftw_cbdata *data);

/*
 * returns 
 *  CL_SUCCESS if it traversed all files and subdirs
 *  CL_BREAK if traversal has stopped at some point
 *  CL_E* if error encountered during traversal and we had to break out
 * This is regardless of virus found/not, that is the callback's job to store.
 * Note that the callback may dispatch async the scan, so that when cli_ftw
 * returns we don't know the infected/notinfected status of the directory yet!
 * Due to this if the callback scans synchronously it should store the infected
 * status in its cbdata.
 * This works for both files and directories. It stats the path to determine
 * which one it is.
 * If it is a file, it simply calls the callback once, otherwise recurses.
 */
int cli_ftw(char *base, int flags, int maxdepth, cli_ftw_cb callback, struct cli_ftw_cbdata *data, cli_ftw_pathchk pathchk);

const char *cli_strerror(int errnum, char* buf, size_t len);
#endif
