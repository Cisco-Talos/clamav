/*
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

#ifndef __CLAMAV_H
#define __CLAMAV_H

/* Certain OSs already use 64bit variables in their stat struct */
#define STAT64_BLACKLIST !defined(__FreeBSD__) && !defined(__APPLE__)

#if defined(HAVE_STAT64) && STAT64_BLACKLIST

#include <unistd.h>

#define STATBUF struct stat64
#define CLAMSTAT stat64
#define LSTAT lstat64
#define FSTAT fstat64
#define safe_open(a, b) open(a, b|O_LARGEFILE)
#else

#define STATBUF struct stat
#define CLAMSTAT stat
#define LSTAT lstat
#define FSTAT fstat
/* Nothing is safe in windows, not even open, safe_open defined under /win32 */
#ifndef _WIN32
#define safe_open open
#endif

#endif

#include <sys/types.h>
#include <sys/stat.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define CL_COUNT_PRECISION 4096

/* return codes */
typedef enum {
    /* libclamav specific */
    CL_CLEAN = 0,
    CL_SUCCESS = 0,
    CL_VIRUS,
    CL_ENULLARG,
    CL_EARG,
    CL_EMALFDB,
    CL_ECVD,
    CL_EVERIFY,
    CL_EUNPACK,

    /* I/O and memory errors */
    CL_EOPEN,
    CL_ECREAT,
    CL_EUNLINK,
    CL_ESTAT,
    CL_EREAD,
    CL_ESEEK,
    CL_EWRITE,
    CL_EDUP,
    CL_EACCES,
    CL_ETMPFILE,
    CL_ETMPDIR,
    CL_EMAP,
    CL_EMEM,
    CL_ETIMEOUT,

    /* internal (not reported outside libclamav) */
    CL_BREAK,
    CL_EMAXREC,
    CL_EMAXSIZE,
    CL_EMAXFILES,
    CL_EFORMAT,
    CL_EPARSE,
    CL_EBYTECODE,/* may be reported in testmode */
    CL_EBYTECODE_TESTFAIL, /* may be reported in testmode */

    /* c4w error codes */
    CL_ELOCK,
    CL_EBUSY,
    CL_ESTATE,

    /* no error codes below this line please */
    CL_ELAST_ERROR
} cl_error_t;

/* db options */
#define CL_DB_PHISHING	    0x2
#define CL_DB_PHISHING_URLS 0x8
#define CL_DB_PUA	    0x10
#define CL_DB_CVDNOTMP	    0x20    /* obsolete */
#define CL_DB_OFFICIAL	    0x40    /* internal */
#define CL_DB_PUA_MODE	    0x80
#define CL_DB_PUA_INCLUDE   0x100
#define CL_DB_PUA_EXCLUDE   0x200
#define CL_DB_COMPILED	    0x400   /* internal */
#define CL_DB_DIRECTORY	    0x800   /* internal */
#define CL_DB_OFFICIAL_ONLY 0x1000
#define CL_DB_BYTECODE      0x2000
#define CL_DB_SIGNED	    0x4000  /* internal */
#define CL_DB_BYTECODE_UNSIGNED	0x8000
#define CL_DB_UNSIGNED	    0x10000 /* internal */
#define CL_DB_BYTECODE_STATS 0x20000
#define CL_DB_ENHANCED      0x40000

/* recommended db settings */
#define CL_DB_STDOPT	    (CL_DB_PHISHING | CL_DB_PHISHING_URLS | CL_DB_BYTECODE)

/* scan options */
#define CL_SCAN_RAW			0x0
#define CL_SCAN_ARCHIVE			0x1
#define CL_SCAN_MAIL			0x2
#define CL_SCAN_OLE2			0x4
#define CL_SCAN_BLOCKENCRYPTED		0x8
#define CL_SCAN_HTML			0x10
#define CL_SCAN_PE			0x20
#define CL_SCAN_BLOCKBROKEN		0x40
#define CL_SCAN_MAILURL			0x80 /* ignored */
#define CL_SCAN_BLOCKMAX		0x100 /* ignored */
#define CL_SCAN_ALGORITHMIC		0x200
#define CL_SCAN_PHISHING_BLOCKSSL	0x800 /* ssl mismatches, not ssl by itself*/
#define CL_SCAN_PHISHING_BLOCKCLOAK	0x1000
#define CL_SCAN_ELF			0x2000
#define CL_SCAN_PDF			0x4000
#define CL_SCAN_STRUCTURED		0x8000
#define CL_SCAN_STRUCTURED_SSN_NORMAL	0x10000
#define CL_SCAN_STRUCTURED_SSN_STRIPPED	0x20000
#define CL_SCAN_PARTIAL_MESSAGE         0x40000
#define CL_SCAN_HEURISTIC_PRECEDENCE    0x80000
#define CL_SCAN_BLOCKMACROS		0x100000
#define CL_SCAN_ALLMATCHES		0x200000
#define CL_SCAN_SWF			0x400000
#define CL_SCAN_PARTITION_INTXN         0x800000

#define CL_SCAN_PERFORMANCE_INFO        0x40000000 /* collect performance timings */
#define CL_SCAN_INTERNAL_COLLECT_SHA    0x80000000 /* Enables hash output in sha-collect builds - for internal use only */

/* recommended scan settings */
#define CL_SCAN_STDOPT		(CL_SCAN_ARCHIVE | CL_SCAN_MAIL | CL_SCAN_OLE2 | CL_SCAN_PDF | CL_SCAN_HTML | CL_SCAN_PE | CL_SCAN_ALGORITHMIC | CL_SCAN_ELF | CL_SCAN_SWF)

/* cl_countsigs options */
#define CL_COUNTSIGS_OFFICIAL	    0x1
#define CL_COUNTSIGS_UNOFFICIAL	    0x2
#define CL_COUNTSIGS_ALL	    (CL_COUNTSIGS_OFFICIAL | CL_COUNTSIGS_UNOFFICIAL)

/* For the new engine_options bit field in the engine */
#define ENGINE_OPTIONS_NONE             0x0
#define ENGINE_OPTIONS_DISABLE_CACHE    0x1
#define ENGINE_OPTIONS_FORCE_TO_DISK    0x2
#define ENGINE_OPTIONS_DISABLE_PE_STATS 0x4

struct cl_engine;
struct cl_settings;

#define CL_INIT_DEFAULT	0x0
extern int cl_init(unsigned int initoptions);

extern struct cl_engine *cl_engine_new(void);

extern void cl_always_gen_section_hash(void);

enum cl_engine_field {
    CL_ENGINE_MAX_SCANSIZE,	    /* uint64_t */
    CL_ENGINE_MAX_FILESIZE,	    /* uint64_t */
    CL_ENGINE_MAX_RECURSION,	    /* uint32_t	*/
    CL_ENGINE_MAX_FILES,	    /* uint32_t */
    CL_ENGINE_MIN_CC_COUNT,	    /* uint32_t */
    CL_ENGINE_MIN_SSN_COUNT,	    /* uint32_t */
    CL_ENGINE_PUA_CATEGORIES,	    /* (char *) */
    CL_ENGINE_DB_OPTIONS,	    /* uint32_t */
    CL_ENGINE_DB_VERSION,	    /* uint32_t */
    CL_ENGINE_DB_TIME,		    /* time_t */
    CL_ENGINE_AC_ONLY,		    /* uint32_t */
    CL_ENGINE_AC_MINDEPTH,	    /* uint32_t */
    CL_ENGINE_AC_MAXDEPTH,	    /* uint32_t */
    CL_ENGINE_TMPDIR,		    /* (char *) */
    CL_ENGINE_KEEPTMP,		    /* uint32_t */
    CL_ENGINE_BYTECODE_SECURITY,    /* uint32_t */
    CL_ENGINE_BYTECODE_TIMEOUT,     /* uint32_t */
    CL_ENGINE_BYTECODE_MODE,        /* uint32_t */
    CL_ENGINE_MAX_EMBEDDEDPE,       /* uint64_t */
    CL_ENGINE_MAX_HTMLNORMALIZE,    /* uint64_t */
    CL_ENGINE_MAX_HTMLNOTAGS,       /* uint64_t */
    CL_ENGINE_MAX_SCRIPTNORMALIZE,  /* uint64_t */
    CL_ENGINE_MAX_ZIPTYPERCG,       /* uint64_t */
    CL_ENGINE_FORCETODISK,          /* uint32_t */
    CL_ENGINE_DISABLE_CACHE,        /* uint32_t */
    CL_ENGINE_DISABLE_PE_STATS,     /* uint32_t */
    CL_ENGINE_STATS_TIMEOUT,        /* uint32_t */
    CL_ENGINE_MAX_PARTITIONS,       /* uint32_t */
    CL_ENGINE_MAX_ICONSPE           /* uint32_t */
};

enum bytecode_security {
    CL_BYTECODE_TRUST_ALL=0, /* obsolete */
    CL_BYTECODE_TRUST_SIGNED, /* default */
    CL_BYTECODE_TRUST_NOTHING /* paranoid setting */
};

enum bytecode_mode {
    CL_BYTECODE_MODE_AUTO=0, /* JIT if possible, fallback to interpreter */
    CL_BYTECODE_MODE_JIT, /* force JIT */
    CL_BYTECODE_MODE_INTERPRETER, /* force interpreter */
    CL_BYTECODE_MODE_TEST, /* both JIT and interpreter, compare results,
			      all failures are fatal */
    CL_BYTECODE_MODE_OFF /* for query only, not settable */
};

struct cli_section_hash {
    unsigned char md5[16];
    size_t len;
};

typedef struct cli_stats_sections {
    size_t nsections;
    struct cli_section_hash *sections;
} stats_section_t;

extern int cl_engine_set_num(struct cl_engine *engine, enum cl_engine_field field, long long num);

extern long long cl_engine_get_num(const struct cl_engine *engine, enum cl_engine_field field, int *err);

extern int cl_engine_set_str(struct cl_engine *engine, enum cl_engine_field field, const char *str);

extern const char *cl_engine_get_str(const struct cl_engine *engine, enum cl_engine_field field, int *err);

extern struct cl_settings *cl_engine_settings_copy(const struct cl_engine *engine);

extern int cl_engine_settings_apply(struct cl_engine *engine, const struct cl_settings *settings);

extern int cl_engine_settings_free(struct cl_settings *settings);

extern int cl_engine_compile(struct cl_engine *engine);

extern int cl_engine_addref(struct cl_engine *engine);

extern int cl_engine_free(struct cl_engine *engine);

extern void cli_cache_disable(void);

extern int cli_cache_enable(struct cl_engine *engine);

/* CALLBACKS */

/* I certainly wish I could declare the callback protoes stable and
   move on to better things. But real life crossed my way enough times
   already and what looked perfect had to evolve somehow.
   So all I can say is I'll try my best not to break these things in the long run.
   But I just can't guarantee that won't happen (again). */

typedef cl_error_t (*clcb_pre_cache)(int fd, const char *type, void *context);
/* PRE-CACHE
   Called for each processed file (both the entry level - AKA 'outer' - file and
   inner files - those generated when processing archive and container files), before
   the actual scanning takes place.

Input:
fd      = File descriptor which is about to be scanned
type    = File type detected via magic - i.e. NOT on the fly - (e.g. "CL_TYPE_MSEXE")
context = Opaque application provided data

Output:
CL_CLEAN = File is scanned
CL_BREAK = Whitelisted by callback - file is skipped and marked as clean
CL_VIRUS = Blacklisted by callback - file is skipped and marked as infected
*/
extern void cl_engine_set_clcb_pre_cache(struct cl_engine *engine, clcb_pre_cache callback);

typedef cl_error_t (*clcb_pre_scan)(int fd, const char *type, void *context);
/* PRE-SCAN
   Called for each NEW file (inner and outer) before the scanning takes place. This is
   roughly the the same as clcb_before_cache, but it is affected by clean file caching.
   This means that it won't be called if a clean cached file (inner or outer) is
   scanned a second time.

Input:
fd      = File descriptor which is about to be scanned
type    = File type detected via magic - i.e. NOT on the fly - (e.g. "CL_TYPE_MSEXE")
context = Opaque application provided data

Output:
CL_CLEAN = File is scanned
CL_BREAK = Whitelisted by callback - file is skipped and marked as clean
CL_VIRUS = Blacklisted by callback - file is skipped and marked as infected
*/
extern void cl_engine_set_clcb_pre_scan(struct cl_engine *engine, clcb_pre_scan callback);

typedef cl_error_t (*clcb_post_scan)(int fd, int result, const char *virname, void *context);
/* POST-SCAN
   Called for each processed file (inner and outer), after the scanning is complete.

Input:
fd      = File descriptor which is was scanned
result  = The scan result for the file
virname = Virus name if infected
context = Opaque application provided data

Output:
CL_CLEAN = Scan result is not overridden
CL_BREAK = Whitelisted by callback - scan result is set to CL_CLEAN
CL_VIRUS = Blacklisted by callback - scan result is set to CL_VIRUS
*/
extern void cl_engine_set_clcb_post_scan(struct cl_engine *engine, clcb_post_scan callback);


typedef int (*clcb_sigload)(const char *type, const char *name, unsigned int custom, void *context);
/* SIGNATURE LOAD
Input:
type = The signature type (e.g. "db", "ndb", "mdb", etc.)
name = The virus name
custom = The signature is official (custom == 0) or custom (custom != 0)
context = Opaque application provided data

Output:
0     = Load the current signature
Non 0 = Skip the current signature

WARNING: Some signatures (notably ldb, cbc) can be dependent upon other signatures.
         Failure to preserve dependency chains will result in database loading failure.
         It is the implementor's responsibility to guarantee consistency.
*/
extern void cl_engine_set_clcb_sigload(struct cl_engine *engine, clcb_sigload callback, void *context);

/* LibClamAV messages callback
 * The specified callback will be called instead of logging to stderr.
 * Messages of lower severity than specified are logged as usual.
 *
 * Just like with cl_debug() this must be called before going multithreaded.
 * Callable before cl_init, if you want to log messages from cl_init() itself.
 *
 * You can use context of cl_scandesc_callback to convey more information to the callback (such as the filename!)
 * Note: setting a 2nd callbacks overwrites previous, multiple callbacks are not
 * supported
 */
enum cl_msg {
    /* leave room for more message levels in the future */
    CL_MSG_INFO_VERBOSE = 32, /* verbose */
    CL_MSG_WARN = 64, /* LibClamAV WARNING: */
    CL_MSG_ERROR = 128/* LibClamAV ERROR: */
};
typedef void (*clcb_msg)(enum cl_msg severity, const char *fullmsg, const char *msg, void *context);
extern void cl_set_clcb_msg(clcb_msg callback);

/* LibClamAV hash stats callback */
typedef void (*clcb_hash)(int fd, unsigned long long size, const unsigned char *md5, const char *virname, void *context);
extern void cl_engine_set_clcb_hash(struct cl_engine *engine, clcb_hash callback);

/* Archive member metadata callback. Return CL_VIRUS to blacklist, CL_CLEAN to
 * continue scanning */
typedef cl_error_t (*clcb_meta)(const char* container_type, unsigned long fsize_container, const char *filename,
			  unsigned long fsize_real,  int is_encrypted, unsigned int filepos_container, void *context);
extern void cl_engine_set_clcb_meta(struct cl_engine *engine, clcb_meta callback);

/* Statistics/intelligence gathering callbacks */
extern void cl_engine_set_stats_set_cbdata(struct cl_engine *engine, void *cbdata);

typedef void (*clcb_stats_add_sample)(const char *virname, const unsigned char *md5, size_t size, stats_section_t *sections, void *cbdata);
extern void cl_engine_set_clcb_stats_add_sample(struct cl_engine *engine, clcb_stats_add_sample callback);

typedef void (*clcb_stats_remove_sample)(const char *virname, const unsigned char *md5, size_t size, void *cbdata);
extern void cl_engine_set_clcb_stats_remove_sample(struct cl_engine *engine, clcb_stats_remove_sample callback);

typedef void (*clcb_stats_decrement_count)(const char *virname, const unsigned char *md5, size_t size, void *cbdata);
extern void cl_engine_set_clcb_stats_decrement_count(struct cl_engine *engine, clcb_stats_decrement_count callback);

typedef void (*clcb_stats_submit)(struct cl_engine *engine, void *cbdata);
extern void cl_engine_set_clcb_stats_submit(struct cl_engine *engine, clcb_stats_submit callback);

typedef void (*clcb_stats_flush)(struct cl_engine *engine, void *cbdata);
extern void cl_engine_set_clcb_stats_flush(struct cl_engine *engine, clcb_stats_flush callback);

typedef size_t (*clcb_stats_get_num)(void *cbdata);
extern void cl_engine_set_clcb_stats_get_num(struct cl_engine *engine, clcb_stats_get_num callback);

typedef size_t (*clcb_stats_get_size)(void *cbdata);
extern void cl_engine_set_clcb_stats_get_size(struct cl_engine *engine, clcb_stats_get_size callback);

typedef char * (*clcb_stats_get_hostid)(void *cbdata);
extern void cl_engine_set_clcb_stats_get_hostid(struct cl_engine *engine, clcb_stats_get_hostid callback);

extern void cl_engine_stats_enable(struct cl_engine *engine);

struct cl_stat {
    char *dir;
    STATBUF *stattab;
    char **statdname;
    unsigned int entries;
};

struct cl_cvd {		    /* field no. */
    char *time;		    /* 2 */
    unsigned int version;   /* 3 */
    unsigned int sigs;	    /* 4 */
    unsigned int fl;	    /* 5 */
			    /* padding */
    char *md5;		    /* 6 */
    char *dsig;		    /* 7 */
    char *builder;	    /* 8 */
    unsigned int stime;	    /* 9 */
};

/* file scanning */
extern int cl_scandesc(int desc, const char **virname, unsigned long int *scanned, const struct cl_engine *engine, unsigned int scanoptions);
extern int cl_scandesc_callback(int desc, const char **virname, unsigned long int *scanned, const struct cl_engine *engine, unsigned int scanoptions, void *context);

extern int cl_scanfile(const char *filename, const char **virname, unsigned long int *scanned, const struct cl_engine *engine, unsigned int scanoptions);
extern int cl_scanfile_callback(const char *filename, const char **virname, unsigned long int *scanned, const struct cl_engine *engine, unsigned int scanoptions, void *context);

/* database handling */
extern int cl_load(const char *path, struct cl_engine *engine, unsigned int *signo, unsigned int dboptions);
extern const char *cl_retdbdir(void);

/* engine handling */

/* CVD */
extern struct cl_cvd *cl_cvdhead(const char *file);
extern struct cl_cvd *cl_cvdparse(const char *head);
extern int cl_cvdverify(const char *file);
extern void cl_cvdfree(struct cl_cvd *cvd);

/* db dir stat functions */
extern int cl_statinidir(const char *dirname, struct cl_stat *dbstat);
extern int cl_statchkdir(const struct cl_stat *dbstat);
extern int cl_statfree(struct cl_stat *dbstat);

/* count signatures */
extern int cl_countsigs(const char *path, unsigned int countoptions, unsigned int *sigs);

/* enable debug messages */
extern void cl_debug(void);

/* software versions */
extern unsigned int cl_retflevel(void);
extern const char *cl_retver(void);

/* others */
extern const char *cl_strerror(int clerror);

/* custom data scanning */
struct cl_fmap;
typedef struct cl_fmap cl_fmap_t;

/* handle - the handle passed to cl_fmap_open_handle, its meaning is up to the
 *    callback's implementation
 * buf, count, offset - read 'count' bytes starting at 'offset' into the buffer 'buf'
 * Thread safety: it is guaranteed that only one callback is executing for a specific handle at
 * any time, but there might be multiple callbacks executing for different
 * handle at the same time.
 */
typedef off_t (*clcb_pread)(void* handle, void *buf, size_t count, off_t offset);

/* Open a map for scanning custom data accessed by a handle and pread (lseek +
 * read)-like interface. For example a WIN32 HANDLE.
 * By default fmap will use aging to discard old data, unless you tell it not
 * to.
 * The handle will be passed to the callback each time.
 */
extern cl_fmap_t *cl_fmap_open_handle(void* handle, size_t offset, size_t len,
				      clcb_pread, int use_aging);

/* Open a map for scanning custom data, where the data is already in memory,
 * either in the form of a buffer, a memory mapped file, etc.
 * Note that the memory [start, start+len) must be the _entire_ file,
 * you can't give it parts of a file and expect detection to work.
 */
extern cl_fmap_t *cl_fmap_open_memory(const void *start, size_t len);

/* Releases resources associated with the map, you should release any resources
 * you hold only after (handles, maps) calling this function */
extern void cl_fmap_close(cl_fmap_t*);

/* Scan custom data */
extern int cl_scanmap_callback(cl_fmap_t *map, const char **virname, unsigned long int *scanned, const struct cl_engine *engine, unsigned int scanoptions, void *context);

#ifdef __cplusplus
}
#endif
 
#endif /* __CLAMAV_H */
