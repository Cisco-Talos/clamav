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

#include "matcher.h"

#ifndef __OTHERS_H_LC
#define __OTHERS_H_LC

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include "cltypes.h"

#include "clamav.h"
#include "dconf.h"
#include "libclamunrar_iface/unrar_iface.h"
#include "regex/regex.h"

/*
 * CL_FLEVEL is the signature f-level specific to the current code and
 *	     should never be modified
 * CL_FLEVEL_DCONF is used in the dconf module and can be bumped by
 * distribution packagers provided they fix *all* security issues found
 * in the old versions of ClamAV. Updating CL_FLEVEL_DCONF will result
 * in re-enabling affected modules.
 */

#define CL_FLEVEL 43
#define CL_FLEVEL_DCONF	CL_FLEVEL

extern uint8_t cli_debug_flag;

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

#define CLI_MAX_ALLOCATION 184549376

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

/* internal clamav context */
typedef struct {
    const char **virname;
    unsigned long int *scanned;
    const struct cli_matcher *root;
    const struct cl_engine *engine;
    unsigned long scansize;
    unsigned int options;
    unsigned int recursion;
    unsigned int scannedfiles;
    unsigned int found_possibly_unwanted;
    struct cli_dconf *dconf;
} cli_ctx;

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

    /* B-M matcher for standard MD5 sigs */
    struct cli_matcher *md5_hdb;

    /* B-M matcher for MD5 sigs for PE sections */
    struct cli_matcher *md5_mdb;

    /* B-M matcher for whitelist db */
    struct cli_matcher *md5_fp;

    /* Zip metadata */
    struct cli_meta_node *zip_mlist;

    /* RAR metadata */
    struct cli_meta_node *rar_mlist;

    /* Phishing .pdb and .wdb databases*/
    struct regex_matcher *whitelist_matcher;
    struct regex_matcher *domainlist_matcher;
    struct phishcheck *phishcheck;

    /* Dynamic configuration */
    struct cli_dconf *dconf;

    /* Filetype definitions */
    struct cli_ftype *ftypes;

    /* Ignored signatures */
    struct cli_ignored *ignored;

    /* PUA categories (to be included or excluded) */
    char *pua_cats;

    /* Used for memory pools */
    mpool_t *mempool;
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
    char *pua_cats;
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
#define SCAN_STRUCTURED	    (ctx->options & CL_SCAN_STRUCTURED)

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


#if WORDS_BIGENDIAN == 0

#ifndef HAVE_ATTRIB_PACKED 
#define __attribute__(x)
#endif
#ifdef HAVE_PRAGMA_PACK
#pragma pack(1)
#endif
#ifdef HAVE_PRAGMA_PACK_HPPA
#pragma pack 1
#endif

union unaligned_32 {
	uint32_t una_u32;
	int32_t una_s32;
} __attribute__((packed));

union unaligned_16 {
	int16_t una_s16;
} __attribute__((packed));

#ifdef HAVE_PRAGMA_PACK
#pragma pack()
#endif
#ifdef HAVE_PRAGMA_PACK_HPPA
#pragma pack
#endif
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

/* used by: spin, yc (C) aCaB */
#define CLI_ROL(a,b) a = ( a << (b % (sizeof(a)<<3) ))  |  (a >> (  (sizeof(a)<<3)  -  (b % (sizeof(a)<<3 )) ) )
#define CLI_ROR(a,b) a = ( a >> (b % (sizeof(a)<<3) ))  |  (a << (  (sizeof(a)<<3)  -  (b % (sizeof(a)<<3 )) ) )

/* Implementation independent sign-extended signed right shift */
#ifdef HAVE_SAR
#define CLI_SRS(n,s) ((n)>>(s))
#else
#define CLI_SRS(n,s) (((n)>>(s)) ^ (1<<(sizeof(n)*8-1-s)) - (1<<(sizeof(n)*8-1-s)))
#endif
#define CLI_SAR(n,s) n = CLI_SRS(n,s)

#ifndef	FALSE
#define FALSE (0)
#endif

#ifndef	TRUE
#define TRUE (1)
#endif

#ifndef MIN
#define MIN(a, b)	(((a) < (b)) ? (a) : (b))
#endif
#ifndef MAX
#define MAX(a,b)	(((a) > (b)) ? (a) : (b))
#endif

typedef struct bitset_tag
{
        unsigned char *bitset;
        unsigned long length;
} bitset_t;

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

/* tell compiler about branches that are very rarely taken,
 * such as debug paths, and error paths */
#if (__GNUC__ >= 4) || (__GNUC__ == 3 && __GNUC_MINOR__ >= 2)
#define UNLIKELY(cond) __builtin_expect(!!(cond), 0)
#else
#define UNLIKELY(cond) (cond)
#endif

#define cli_dbgmsg (!UNLIKELY(cli_debug_flag)) ? (void)0 : cli_dbgmsg_internal

#ifdef __GNUC__
void cli_dbgmsg_internal(const char *str, ...) __attribute__((format(printf, 1, 2)));
#else
void cli_dbgmsg_internal(const char *str, ...);
#endif

void *cli_malloc(size_t nmemb);
void *cli_calloc(size_t nmemb, size_t size);
void *cli_realloc(void *ptr, size_t size);
void *cli_realloc2(void *ptr, size_t size);
char *cli_strdup(const char *s);
int cli_rmdirs(const char *dirname);
unsigned char *cli_md5digest(int desc);
char *cli_md5stream(FILE *fs, unsigned char *digcpy);
char *cli_md5file(const char *filename);
int cli_unlink(const char *pathname);
int cli_readn(int fd, void *buff, unsigned int count);
int cli_writen(int fd, const void *buff, unsigned int count);
char *cli_gentemp(const char *dir);
int cli_gentempfd(const char *dir, char **name, int *fd);
unsigned int cli_rndnum(unsigned int max);
int cli_filecopy(const char *src, const char *dest);
bitset_t *cli_bitset_init(void);
void cli_bitset_free(bitset_t *bs);
int cli_bitset_set(bitset_t *bs, unsigned long bit_offset);
int cli_bitset_test(bitset_t *bs, unsigned long bit_offset);
const char* cli_ctime(const time_t *timep, char *buf, const size_t bufsize);
int cli_checklimits(const char *, cli_ctx *, unsigned long, unsigned long, unsigned long);
int cli_updatelimits(cli_ctx *, unsigned long);
unsigned long cli_getsizelimit(cli_ctx *, unsigned long);
int cli_matchregex(const char *str, const char *regex);

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
typedef int (*cli_ftw_cb)(struct stat *stat_buf, char *filename, const char *path, enum cli_ftw_reason reason, struct cli_ftw_cbdata *data);

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
int cli_ftw(char *base, int flags, int maxdepth, cli_ftw_cb callback, struct cli_ftw_cbdata *data);

const char *cli_strerror(int errnum, char* buf, size_t len);
#endif
