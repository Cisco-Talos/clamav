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

#ifndef __CLAMAV_H
#define __CLAMAV_H

#ifdef _WIN32
#ifndef OWN_WINSOCK
#include <winsock2.h>
#endif
#endif

#include <openssl/ssl.h>
#include <openssl/err.h>

/* Certain OSs already use 64bit variables in their stat struct */
#if ( !defined(__FreeBSD__) && !defined(__APPLE__) )
#define STAT64_BLACKLIST 1
#else
#define STAT64_BLACKLIST 0
#endif

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

#define UNUSEDPARAM(x) (void)(x)

#include <sys/types.h>
#include <sys/stat.h>

#include "clamav-types.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define CL_COUNT_PRECISION 4096

/* return codes */
typedef enum cl_error_t {
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
#define CL_DB_PHISHING          0x2
#define CL_DB_PHISHING_URLS     0x8
#define CL_DB_PUA               0x10
#define CL_DB_CVDNOTMP          0x20    /* obsolete */
#define CL_DB_OFFICIAL          0x40    /* internal */
#define CL_DB_PUA_MODE          0x80
#define CL_DB_PUA_INCLUDE       0x100
#define CL_DB_PUA_EXCLUDE       0x200
#define CL_DB_COMPILED          0x400   /* internal */
#define CL_DB_DIRECTORY         0x800   /* internal */
#define CL_DB_OFFICIAL_ONLY     0x1000
#define CL_DB_BYTECODE          0x2000
#define CL_DB_SIGNED            0x4000  /* internal */
#define CL_DB_BYTECODE_UNSIGNED 0x8000
#define CL_DB_UNSIGNED          0x10000 /* internal */
#define CL_DB_BYTECODE_STATS    0x20000
#define CL_DB_ENHANCED          0x40000
#define CL_DB_PCRE_STATS        0x80000
#define CL_DB_YARA_EXCLUDE      0x100000
#define CL_DB_YARA_ONLY         0x200000

/* recommended db settings */
#define CL_DB_STDOPT (CL_DB_PHISHING | CL_DB_PHISHING_URLS | CL_DB_BYTECODE)

/*** scan options ***/
struct cl_scan_options {
    uint32_t general;
    uint32_t parse;
    uint32_t heuristic;
    uint32_t mail;
    uint32_t dev;
};

/* general */
#define CL_SCAN_GENERAL_ALLMATCHES                  0x1  /* scan in all-match mode */
#define CL_SCAN_GENERAL_COLLECT_METADATA            0x2  /* collect metadata (--gen-json) */
#define CL_SCAN_GENERAL_HEURISTICS                  0x4  /* option to enable heuristic alerts */
#define CL_SCAN_GENERAL_HEURISTIC_PRECEDENCE        0x8  /* allow heuristic match to take precedence. */
#define CL_SCAN_GENERAL_UNPRIVILEGED                0x10 /* scanner will not have read access to files. */

/* parsing capabilities options */
#define CL_SCAN_PARSE_ARCHIVE                       0x1
#define CL_SCAN_PARSE_ELF                           0x2
#define CL_SCAN_PARSE_PDF                           0x4
#define CL_SCAN_PARSE_SWF                           0x8
#define CL_SCAN_PARSE_HWP3                          0x10
#define CL_SCAN_PARSE_XMLDOCS                       0x20
#define CL_SCAN_PARSE_MAIL                          0x40
#define CL_SCAN_PARSE_OLE2                          0x80
#define CL_SCAN_PARSE_HTML                          0x100
#define CL_SCAN_PARSE_PE                            0x200

/* heuristic alerting options */
#define CL_SCAN_HEURISTIC_BROKEN                    0x2   /* alert on broken PE and broken ELF files */
#define CL_SCAN_HEURISTIC_EXCEEDS_MAX               0x4   /* alert when files exceed scan limits (filesize, max scansize, or max recursion depth) */
#define CL_SCAN_HEURISTIC_PHISHING_SSL_MISMATCH     0x8   /* alert on SSL mismatches */
#define CL_SCAN_HEURISTIC_PHISHING_CLOAK            0x10  /* alert on cloaked URLs in emails */
#define CL_SCAN_HEURISTIC_MACROS                    0x20  /* alert on OLE2 files containing macros */
#define CL_SCAN_HEURISTIC_ENCRYPTED_ARCHIVE         0x40  /* alert if archive is encrypted (rar, zip, etc) */
#define CL_SCAN_HEURISTIC_ENCRYPTED_DOC             0x80  /* alert if a document is encrypted (pdf, docx, etc) */
#define CL_SCAN_HEURISTIC_PARTITION_INTXN           0x100 /* alert if partition table size doesn't make sense */
#define CL_SCAN_HEURISTIC_STRUCTURED                0x200 /* data loss prevention options, i.e. alert when detecting personal information */
#define CL_SCAN_HEURISTIC_STRUCTURED_SSN_NORMAL     0x400 /* alert when detecting social security numbers */
#define CL_SCAN_HEURISTIC_STRUCTURED_SSN_STRIPPED   0x800 /* alert when detecting stripped social security numbers */

/* mail scanning options */
#define CL_SCAN_MAIL_PARTIAL_MESSAGE                0x1

/* dev options */
#define CL_SCAN_DEV_COLLECT_SHA                     0x1 /* Enables hash output in sha-collect builds - for internal use only */
#define CL_SCAN_DEV_COLLECT_PERFORMANCE_INFO        0x2 /* collect performance timings */

/* cl_countsigs options */
#define CL_COUNTSIGS_OFFICIAL	    0x1
#define CL_COUNTSIGS_UNOFFICIAL	    0x2
#define CL_COUNTSIGS_ALL	    (CL_COUNTSIGS_OFFICIAL | CL_COUNTSIGS_UNOFFICIAL)

/* For the new engine_options bit field in the engine */
#define ENGINE_OPTIONS_NONE             0x0
#define ENGINE_OPTIONS_DISABLE_CACHE    0x1
#define ENGINE_OPTIONS_FORCE_TO_DISK    0x2
#define ENGINE_OPTIONS_DISABLE_PE_STATS 0x4
#define ENGINE_OPTIONS_DISABLE_PE_CERTS 0x8
#define ENGINE_OPTIONS_PE_DUMPCERTS     0x10

struct cl_engine;
struct cl_settings;

/* ----------------------------------------------------------------------------
 * Enable global libclamav features.
 */

/**
 * @brief Enable debug messages
 */
extern void cl_debug(void);

/**
 * @brief Set libclamav to always create section hashes for PE files.
 *
 * Section hashes are used in .mdb signature.
 */
extern void cl_always_gen_section_hash(void);

/* ----------------------------------------------------------------------------
 * Scan engine functions.
 */

/**
 * @brief This function initializes the openssl crypto system.
 *
 * Called by cl_init() and does not need to be cleaned up as de-init
 * is handled automatically by openssl 1.0.2.h and 1.1.0
 *
 * @return Always returns 0
 */
int cl_initialize_crypto(void);

/**
 * @brief This is a deprecated function that used to clean up ssl crypto inits.
 *
 * Call to EVP_cleanup() has been removed since cleanup is now handled by
 * auto-deinit as of openssl 1.0.2h and 1.1.0
 */
void cl_cleanup_crypto(void);

#define CL_INIT_DEFAULT	0x0
/**
 * @brief Initialize the ClamAV library.
 *
 * @param initoptions   Unused.
 * @return cl_error_t   CL_SUCCESS if everything initalized correctly.
 */
extern int cl_init(unsigned int initoptions);

/**
 * @brief Allocate a new scanning engine and initialize default settings.
 *
 * The engine should be freed with `cl_engine_free()`.
 *
 * @return struct cl_engine* Pointer to the scanning engine.
 */
extern struct cl_engine *cl_engine_new(void);

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
    CL_ENGINE_MAX_ICONSPE,          /* uint32_t */
    CL_ENGINE_MAX_RECHWP3,          /* uint32_t */
    CL_ENGINE_MAX_SCANTIME,         /* uint32_t */
    CL_ENGINE_PCRE_MATCH_LIMIT,     /* uint64_t */
    CL_ENGINE_PCRE_RECMATCH_LIMIT,  /* uint64_t */
    CL_ENGINE_PCRE_MAX_FILESIZE,    /* uint64_t */
    CL_ENGINE_DISABLE_PE_CERTS,     /* uint32_t */
    CL_ENGINE_PE_DUMPCERTS          /* uint32_t */
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

/**
 * @brief Set a numerical engine option.
 *
 * @param engine            An initialized scan engine.
 * @param cl_engine_field   A CL_ENGINE option.
 * @param num               The new engine option value.
 * @return cl_error_t       CL_SUCCESS if successfully set.
 * @return cl_error_t       CL_EARG if the field number was incorrect.
 * @return cl_error_t       CL_ENULLARG null arguments were provided.
 */
extern int cl_engine_set_num(struct cl_engine *engine, enum cl_engine_field field, long long num);

/**
 * @brief Get a numerical engine option.
 *
 * @param engine            An initialized scan engine.
 * @param cl_engine_field   A CL_ENGINE option.
 * @param err               (optional) A cl_error_t status code.
 * @return long long        The numerical option value.
 */
extern long long cl_engine_get_num(const struct cl_engine *engine, enum cl_engine_field field, int *err);

/**
 * @brief Set a string engine option.
 *
 * @param engine            An initialized scan engine.
 * @param cl_engine_field   A CL_ENGINE option.
 * @param str               The new engine option value.
 * @return cl_error_t       CL_SUCCESS if successfully set.
 * @return cl_error_t       CL_EARG if the field number was incorrect.
 * @return cl_error_t       CL_EMEM if a memory allocation error occurred.
 * @return cl_error_t       CL_ENULLARG null arguments were provided.
 */
extern int cl_engine_set_str(struct cl_engine *engine, enum cl_engine_field field, const char *str);

/**
 * @brief Get a string engine option.
 *
 * @param engine            An initialized scan engine.
 * @param cl_engine_field   A CL_ENGINE option.
 * @param err               (optional) A cl_error_t status code.
 * @return const char *     The string option value.
 */
extern const char *cl_engine_get_str(const struct cl_engine *engine, enum cl_engine_field field, int *err);

/**
 * @brief Copy the settings from an existing scan engine.
 *
 * The cl_settings pointer is allocated and must be freed with cl_engine_settings_free().
 *
 * @param engine                An configured scan engine.
 * @return struct cl_settings*  The settings.
 */
extern struct cl_settings *cl_engine_settings_copy(const struct cl_engine *engine);

/**
 * @brief Apply settings from a settings structure to a scan engine.
 *
 * @param engine        A scan engine.
 * @param settings      The settings.
 * @return cl_error_t   CL_SUCCESS if successful.
 * @return cl_error_t   CL_EMEM if a memory allocation error occurred.
 */
extern int cl_engine_settings_apply(struct cl_engine *engine, const struct cl_settings *settings);

/**
 * @brief Free a settings struct pointer.
 *
 * @param settings      The settings struct pointer.
 * @return cl_error_t   CL_SUCCESS if successful.
 * @return cl_error_t   CL_ENULLARG null arguments were provided.
 */
extern int cl_engine_settings_free(struct cl_settings *settings);

/**
 * @brief Prepare the scanning engine.
 *
 * Called this after all required databases have been loaded and settings have
 * been applied.
 *
 * @param engine        A scan engine.
 * @return cl_error_t   CL_SUCCESS if successful.
 * @return cl_error_t   CL_ENULLARG null arguments were provided.
 */
extern int cl_engine_compile(struct cl_engine *engine);

/**
 * @brief Add a reference count to the engine.
 *
 * Thread safety mechanism so that the engine is not free'd by another thread.
 *
 * The engine is initialized with refcount = 1, so this only needs to be called
 * for additional scanning threads.
 *
 * @param engine        A scan engine.
 * @return cl_error_t   CL_SUCCESS if successful.
 * @return cl_error_t   CL_ENULLARG null arguments were provided.
 */
extern int cl_engine_addref(struct cl_engine *engine);

/**
 * @brief Free an engine.
 *
 * Will lower the reference count on an engine. If the reference count hits
 * zero, the engine will be freed.
 *
 * @param engine        A scan engine.
 * @return cl_error_t   CL_SUCCESS if successful.
 * @return cl_error_t   CL_ENULLARG null arguments were provided.
 */
extern int cl_engine_free(struct cl_engine *engine);

/* ----------------------------------------------------------------------------
 * Callback function type definitions.
 */

/**
 * @brief Pre-cache callback.
 *
 * Called for each processed file (both the entry level - AKA 'outer' - file and
 * inner files - those generated when processing archive and container files), before
 * the actual scanning takes place.
 *
 * @param fd        File descriptor which is about to be scanned.
 * @param type      File type detected via magic - i.e. NOT on the fly - (e.g. "CL_TYPE_MSEXE").
 * @param context   Opaque application provided data.
 * @return          CL_CLEAN = File is scanned.
 * @return          CL_BREAK = Whitelisted by callback - file is skipped and marked as clean.
 * @return          CL_VIRUS = Blacklisted by callback - file is skipped and marked as infected.
 */
typedef cl_error_t (*clcb_pre_cache)(int fd, const char *type, void *context);
/**
 * @brief Set a custom pre-cache callback function.
 *
 * @param engine    The initialized scanning engine.
 * @param callback  The callback function pointer.
 */
extern void cl_engine_set_clcb_pre_cache(struct cl_engine *engine, clcb_pre_cache callback);

/**
 * @brief Pre-scan callback.
 *
 * Called for each NEW file (inner and outer) before the scanning takes place. This is
 * roughly the the same as clcb_before_cache, but it is affected by clean file caching.
 * This means that it won't be called if a clean cached file (inner or outer) is
 * scanned a second time.
 *
 * @param fd        File descriptor which is about to be scanned.
 * @param type      File type detected via magic - i.e. NOT on the fly - (e.g. "CL_TYPE_MSEXE").
 * @param context   Opaque application provided data.
 * @return          CL_CLEAN = File is scanned.
 * @return          CL_BREAK = Whitelisted by callback - file is skipped and marked as clean.
 * @return          CL_VIRUS = Blacklisted by callback - file is skipped and marked as infected.
 */
typedef cl_error_t (*clcb_pre_scan)(int fd, const char *type, void *context);
/**
 * @brief Set a custom pre-scan callback function.
 *
 * @param engine    The initialized scanning engine.
 * @param callback  The callback function pointer.
 */
extern void cl_engine_set_clcb_pre_scan(struct cl_engine *engine, clcb_pre_scan callback);

/**
 * @brief Post-scan callback.
 *
 * Called for each processed file (inner and outer), after the scanning is complete.
 * In all-match mode, the virname will be one of the matches, but there is no
 * guarantee in which order the matches will occur, thus the final virname may
 * be any one of the matches.
 *
 * @param fd        File descriptor which was scanned.
 * @param result    The scan result for the file.
 * @param virname   A signature name if there was one or more matches.
 * @param context   Opaque application provided data.
 * @return          Scan result is not overridden.
 * @return          CL_BREAK = Whitelisted by callback - scan result is set to CL_CLEAN.
 * @return          Blacklisted by callback - scan result is set to CL_VIRUS.
 */
typedef cl_error_t (*clcb_post_scan)(int fd, int result, const char *virname, void *context);
/**
 * @brief Set a custom post-scan callback function.
 *
 * @param engine    The initialized scanning engine.
 * @param callback  The callback function pointer.
 */
extern void cl_engine_set_clcb_post_scan(struct cl_engine *engine, clcb_post_scan callback);

/**
 * @brief Post-scan callback.
 *
 * Called for each signature match.
 * If all-match is enabled, clcb_virus_found() may be called multiple times per
 * scan.
 *
 * In addition, clcb_virus_found() does not have a return value and thus.
 * can not be used to whitelist the match.
 *
 * @param fd        File descriptor which was scanned.
 * @param virname   Virus name.
 * @param context   Opaque application provided data.
 */
typedef void (*clcb_virus_found)(int fd, const char *virname, void *context);
/**
 * @brief Set a custom virus-found callback function.
 *
 * @param engine    The initialized scanning engine.
 * @param callback  The callback function pointer.
 */
extern void cl_engine_set_clcb_virus_found(struct cl_engine *engine, clcb_virus_found callback);

/**
 * @brief Signature-load callback.
 *
 * May be used to ignore signatures at database load time.
 *
 * WARNING: Some signatures (notably ldb, cbc) can be dependent upon other signatures.
 *          Failure to preserve dependency chains will result in database loading failure.
 *          It is the implementor's responsibility to guarantee consistency.
 *
 * @param type      The signature type (e.g. "db", "ndb", "mdb", etc.)
 * @param name      Signature name.
 * @param custom    The signature is official (custom == 0) or custom (custom != 0)
 * @param context   Opaque application provided data
 * @return          0 to load the current signature.
 * @return          Non-0 to skip the current signature.
 */
typedef int (*clcb_sigload)(const char *type, const char *name, unsigned int custom, void *context);
/**
 * @brief Set a custom signature-load callback function.
 *
 * @param engine    The initialized scanning engine.
 * @param callback  The callback function pointer.
 * @param context   Opaque application provided data.
 */
extern void cl_engine_set_clcb_sigload(struct cl_engine *engine, clcb_sigload callback, void *context);

enum cl_msg {
    /* leave room for more message levels in the future */
    CL_MSG_INFO_VERBOSE = 32, /* verbose */
    CL_MSG_WARN = 64, /* LibClamAV WARNING: */
    CL_MSG_ERROR = 128/* LibClamAV ERROR: */
};

/**
 * @brief Logging message callback for info, warning, and error messages.
 *
 * The specified callback will be called instead of logging to stderr.
 * Messages of lower severity than specified are logged as usual.
 *
 * Callback may be used to silence logging by assigning a do-nothing function.
 * Does not affect debug log messages.
 *
 * Just like with cl_debug() this must be called before going multithreaded.
 * Callable before cl_init, if you want to log messages from cl_init() itself.
 *
 * You can use context of cl_scandesc_callback to convey more information to
 * the callback (such as the filename!).
 *
 * Note: setting a 2nd callbacks overwrites previous, multiple callbacks are not
 * supported.
 *
 * @param severity  Message severity (CL_MSG_INFO_VERBOSE, CL_MSG_WARN, or CL_MSG_ERROR).
 * @param fullmsg   The log message including the "LibClamAV <severity>: " prefix.
 * @param msg       The log message.
 * @param context   Opaque application provided data.
 */
typedef void (*clcb_msg)(enum cl_msg severity, const char *fullmsg, const char *msg, void *context);
/**
 * @brief Set a custom logging message callback function for all of libclamav.
 *
 * @param callback  The callback function pointer.
 */
extern void cl_set_clcb_msg(clcb_msg callback);

/**
 * @brief LibClamAV hash stats callback.
 *
 * Callback that provides the hash of a scanned sample if a signature alerted.
 * Provides a mechanism to record detection statistics.
 *
 * @param fd        File descriptor if available, else -1.
 * @param size      Sample size
 * @param md5       Sample md5 hash
 * @param virname   Signature name that the sample matched against
 * @param context   Opaque application provided data
 */
typedef void (*clcb_hash)(int fd, unsigned long long size, const unsigned char *md5, const char *virname, void *context);
/**
 * @brief Set a custom hash stats callback function.
 *
 * @param engine    The initialized scanning engine.
 * @param callback  The callback function pointer.
 */
extern void cl_engine_set_clcb_hash(struct cl_engine *engine, clcb_hash callback);

/**
 * @brief Archive meta matching callback function.
 *
 * May be used to blacklist archive/container samples based on archive metadata.
 * Function is invoked multiple times per archive. Typically once per contained file.
 *
 * Note: Used by the --archive-verbose clamscan option. Overriding this will alter
 * the output from --archive-verbose.
 *
 * @param container_type    String name of type (CL_TYPE).
 * @param fsize_container   Sample size
 * @param filename          Filename associated with the data in archive.
 * @param fsize_real        Size of file after decompression (according to the archive).
 * @param is_encrypted      Boolean non-zero if the contained file is encrypted.
 * @param filepos_container File index in container.
 * @param context           Opaque application provided data.
 * @return                  CL_VIRUS to blacklist
 * @return                  CL_CLEAN to continue scanning
 */
typedef cl_error_t (*clcb_meta)(const char* container_type, unsigned long fsize_container, const char *filename,
			  unsigned long fsize_real,  int is_encrypted, unsigned int filepos_container, void *context);
/**
 * @brief Set a custom archive metadata matching callback function.
 *
 * @param engine    The initialized scanning engine.
 * @param callback  The callback function pointer.
 */
extern void cl_engine_set_clcb_meta(struct cl_engine *engine, clcb_meta callback);

/**
 * @brief File properties callback function.
 *
 * Invoked after a scan the CL_SCAN_GENERAL_COLLECT_METADATA general scan option
 * is enabled and libclamav was built with json support.
 *
 * @param j_propstr File properties/metadata in a JSON encoded string.
 * @param rc        The cl_error_t return code from the scan.
 * @param cbdata    Opaque application provided data.
 */
typedef int (*clcb_file_props)(const char *j_propstr, int rc, void *cbdata);
/**
 * @brief Set a custom file properties callback function.
 *
 * @param engine    The initialized scanning engine.
 * @param callback  The callback function pointer.
 */
extern void cl_engine_set_clcb_file_props(struct cl_engine *engine, clcb_file_props callback);

/* ----------------------------------------------------------------------------
 * Statistics/telemetry gathering callbacks.
 *
 * The statistics callback functions may be used to implement a telemetry
 * gathering feature.
 *
 * The structure definition for `cbdata` is entirely up to the caller, as are
 * the implementations of each of the callback functions defined below.
 */

/**
 * @brief Set a pointer the caller-defined cbdata structure.
 *
 * The data must persist at least until `clcb_stats_submit()` is called, or
 * `clcb_stats_flush()` is called (optional).
 *
 * @param engine The scanning engine.
 * @param cbdata The statistics data. Probably a pointer to a malloc'd struct.
 */
extern void cl_engine_set_stats_set_cbdata(struct cl_engine *engine, void *cbdata);

/**
 * @brief Add sample metadata to the statistics for a sample that matched on a signature.
 *
 * @param virname   Name of the signature that matched.
 * @param md5       Sample hash.
 * @param size      Sample size.
 * @param sections  PE section data, if applicable.
 * @param cbdata    The statistics data. Probably a pointer to a malloc'd struct.
 */
typedef void (*clcb_stats_add_sample)(const char *virname, const unsigned char *md5, size_t size, stats_section_t *sections, void *cbdata);
/**
 * @brief Set a custom callback function to add sample metadata to a statistics report.
 *
 * @param engine    The initialized scanning engine.
 * @param callback  The callback function pointer.
 */
extern void cl_engine_set_clcb_stats_add_sample(struct cl_engine *engine, clcb_stats_add_sample callback);

/**
 * @brief Remove a specific sample from the statistics report.
 *
 * @param virname   Name of the signature that matched.
 * @param md5       Sample hash.
 * @param size      Sample size.
 * @param cbdata    The statistics data. Probably a pointer to a malloc'd struct.
 */
typedef void (*clcb_stats_remove_sample)(const char *virname, const unsigned char *md5, size_t size, void *cbdata);
/**
 * @brief Set a custom callback function to remove sample metadata from a statistics report.
 *
 * @param engine    The initialized scanning engine.
 * @param callback  The callback function pointer.
 */
extern void cl_engine_set_clcb_stats_remove_sample(struct cl_engine *engine, clcb_stats_remove_sample callback);

/**
 * @brief Decrement the hit count listed in the statistics report for a specific sample.
 *
 * @param virname   Name of the signature that matched.
 * @param md5       Sample hash.
 * @param size      Sample size.
 * @param cbdata    The statistics data. Probably a pointer to a malloc'd struct.
 */
typedef void (*clcb_stats_decrement_count)(const char *virname, const unsigned char *md5, size_t size, void *cbdata);
/**
 * @brief Set a custom callback function to decrement the hit count listed in the statistics report for a specific sample.
 *
 * This function may remove the sample from the report if the hit count is decremented to 0.
 *
 * @param engine    The initialized scanning engine.
 * @param callback  The callback function pointer.
 */
extern void cl_engine_set_clcb_stats_decrement_count(struct cl_engine *engine, clcb_stats_decrement_count callback);

/**
 * @brief Function to submit a statistics report.
 *
 * @param engine    The initialized scanning engine.
 * @param cbdata    The statistics data. Probably a pointer to a malloc'd struct.
 */
typedef void (*clcb_stats_submit)(struct cl_engine *engine, void *cbdata);
/**
 * @brief Set a custom callback function to submit the statistics report.
 *
 * @param engine    The initialized scanning engine.
 * @param callback  The callback function pointer.
 */
extern void cl_engine_set_clcb_stats_submit(struct cl_engine *engine, clcb_stats_submit callback);

/**
 * @brief Function to flush/free the statistics report data.
 *
 * @param engine    The initialized scanning engine.
 * @param cbdata    The statistics data. Probably a pointer to a malloc'd struct.
 */
typedef void (*clcb_stats_flush)(struct cl_engine *engine, void *cbdata);
/**
 * @brief Set a custom callback function to flush/free the statistics report data.
 *
 * @param engine    The initialized scanning engine.
 * @param callback  The callback function pointer.
 */
extern void cl_engine_set_clcb_stats_flush(struct cl_engine *engine, clcb_stats_flush callback);

/**
 * @brief Function to get the number of samples listed in the statistics report.
 *
 * @param cbdata    The statistics data. Probably a pointer to a malloc'd struct.
 */
typedef size_t (*clcb_stats_get_num)(void *cbdata);
/**
 * @brief Set a custom callback function to get the number of samples listed in the statistics report.
 *
 * @param engine    The initialized scanning engine.
 * @param callback  The callback function pointer.
 */
extern void cl_engine_set_clcb_stats_get_num(struct cl_engine *engine, clcb_stats_get_num callback);

/**
 * @brief Function to get the size of memory used to store the statistics report.
 *
 * @param cbdata    The statistics data. Probably a pointer to a malloc'd struct.
 */
typedef size_t (*clcb_stats_get_size)(void *cbdata);
/**
 * @brief Set a custom callback function to get the size of memory used to store the statistics report.
 *
 * @param engine    The initialized scanning engine.
 * @param callback  The callback function pointer.
 */
extern void cl_engine_set_clcb_stats_get_size(struct cl_engine *engine, clcb_stats_get_size callback);

/**
 * @brief Function to get the machine's unique host ID.
 *
 * @param cbdata    The statistics data. Probably a pointer to a malloc'd struct.
 */
typedef char * (*clcb_stats_get_hostid)(void *cbdata);
/**
 * @brief Set a custom callback function to get the machine's unique host ID.
 *
 * @param engine    The initialized scanning engine.
 * @param callback  The callback function pointer.
 */
extern void cl_engine_set_clcb_stats_get_hostid(struct cl_engine *engine, clcb_stats_get_hostid callback);

/**
 * @brief Function enables the built-in statistics reporting feature.
 *
 * @param engine    The initialized scanning engine.
 */
extern void cl_engine_stats_enable(struct cl_engine *engine);

/* ----------------------------------------------------------------------------
 * File scanning.
 */

/**
 * @brief Scan a file, given a file descriptor.
 *
 * @param desc              File descriptor of an open file. The caller must provide this or the map.
 * @param filename          (optional) Filepath of the open file descriptor or file map.
 * @param[out] virname      Will be set to a statically allocated (i.e. needs not be freed) signature name if the scan matches against a signature.
 * @param[out] scanned      The number of bytes scanned.
 * @param engine            The scanning engine.
 * @param scanoptions       Scanning options.
 * @return cl_error_t       CL_CLEAN, CL_VIRUS, or an error code if an error occured during the scan.
 */
extern int cl_scandesc(int desc, const char *filename, const char **virname, unsigned long int *scanned, const struct cl_engine *engine, struct cl_scan_options* scanoptions);

/**
 * @brief Scan a file, given a file descriptor.
 *
 * This callback variant allows the caller to provide a context structure that caller provided callback functions can interpret.
 *
 * @param desc              File descriptor of an open file. The caller must provide this or the map.
 * @param filename          (optional) Filepath of the open file descriptor or file map.
 * @param[out] virname      Will be set to a statically allocated (i.e. needs not be freed) signature name if the scan matches against a signature.
 * @param[out] scanned      The number of bytes scanned.
 * @param engine            The scanning engine.
 * @param scanoptions       Scanning options.
 * @param[in/out] context   An opaque context structure allowing the caller to record details about the sample being scanned.
 * @return cl_error_t       CL_CLEAN, CL_VIRUS, or an error code if an error occured during the scan.
 */
extern int cl_scandesc_callback(int desc, const char *filename, const char **virname, unsigned long int *scanned, const struct cl_engine *engine, struct cl_scan_options* scanoptions, void *context);

/**
 * @brief Scan a file, given a filename.
 *
 * @param filename          Filepath of the file to be scanned.
 * @param[out] virname      Will be set to a statically allocated (i.e. needs not be freed) signature name if the scan matches against a signature.
 * @param[out] scanned      The number of bytes scanned.
 * @param engine            The scanning engine.
 * @param scanoptions       Scanning options.
 * @return cl_error_t       CL_CLEAN, CL_VIRUS, or an error code if an error occured during the scan.
 */
extern int cl_scanfile(const char *filename, const char **virname, unsigned long int *scanned, const struct cl_engine *engine, struct cl_scan_options* scanoptions);

/**
 * @brief Scan a file, given a filename.
 *
 * This callback variant allows the caller to provide a context structure that caller provided callback functions can interpret.
 *
 * @param filename          Filepath of the file to be scanned.
 * @param[out] virname      Will be set to a statically allocated (i.e. needs not be freed) signature name if the scan matches against a signature.
 * @param[out] scanned      The number of bytes scanned.
 * @param engine            The scanning engine.
 * @param scanoptions       Scanning options.
 * @param[in/out] context   An opaque context structure allowing the caller to record details about the sample being scanned.
 * @return cl_error_t       CL_CLEAN, CL_VIRUS, or an error code if an error occured during the scan.
 */
extern int cl_scanfile_callback(const char *filename, const char **virname, unsigned long int *scanned, const struct cl_engine *engine, struct cl_scan_options* scanoptions, void *context);

/* ----------------------------------------------------------------------------
 * Database handling.
 */
extern int cl_load(const char *path, struct cl_engine *engine, unsigned int *signo, unsigned int dboptions);
extern const char *cl_retdbdir(void);

/* ----------------------------------------------------------------------------
 * CVD / database functions
 */

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

/**
 * @brief Read the CVD header data from a file.
 *
 * The returned pointer must be free'd with cl_cvdfree().
 *
 * @param file              Filepath of CVD file.
 * @return struct cl_cvd*   Pointer to an allocated CVD header data structure.
 */
extern struct cl_cvd *cl_cvdhead(const char *file);

/**
 * @brief Parse the CVD header.
 *
 * Buffer length is not an argument, and the check must be done
 * by the caller cl_cvdhead().
 *
 * The returned pointer must be free'd with cl_cvdfree().
 *
 * @param head              Pointer to the header data buffer.
 * @return struct cl_cvd*   Pointer to an allocated CVD header data structure.
 */
extern struct cl_cvd *cl_cvdparse(const char *head);

/**
 * @brief Verify a CVD file by loading and unloading it.
 *
 * @param file          Filepath of CVD file.
 * @return cl_error_t   CL_SUCCESS if success, else a CL_E* error code.
 */
extern int cl_cvdverify(const char *file);

/**
 * @brief Free a CVD header struct.
 *
 * @param cvd   Pointer to a CVD header struct.
 */
extern void cl_cvdfree(struct cl_cvd *cvd);

/* ----------------------------------------------------------------------------
 * DB directory stat functions.
 * Use these functions to watch for database changes.
 */

struct cl_stat {
    char *dir;
    STATBUF *stattab;
    char **statdname;
    unsigned int entries;
};

/**
 * @brief Initialize a directory to be watched for database changes.
 *
 * The dbstat out variable is allocated and must be freed using cl_statfree().
 *
 * @param dirname       Pathname of the database directory.
 * @param[out] dbstat   dbstat handle.
 * @return cl_error_t   CL_SUCCESS if successfully initialized.
 */
extern int cl_statinidir(const char *dirname, struct cl_stat *dbstat);

/**
 * @brief Check the database directory for changes.
 *
 * @param dbstat dbstat handle.
 * @return int   0 No change.
 * @return int   1 Some change occured.
 */
extern int cl_statchkdir(const struct cl_stat *dbstat);

/**
 * @brief Free the dbstat handle.
 *
 * @param dbstat        dbstat handle.
 * @return cl_error_t   CL_SUCCESS
 * @return cl_error_t   CL_ENULLARG
 */
extern int cl_statfree(struct cl_stat *dbstat);

/**
 * @brief Count the number of signatures in a database file or directory.
 *
 * @param path          Path of the database file or directory.
 * @param countoptions  A bitflag field. May be CL_COUNTSIGS_OFFICIAL, CL_COUNTSIGS_UNOFFICIAL, or CL_COUNTSIGS_ALL.
 * @param[out] sigs     The number of sigs.
 * @return cl_error_t   CL_SUCCESS if success, else a CL_E* error type.
 */
extern int cl_countsigs(const char *path, unsigned int countoptions, unsigned int *sigs);

/* ----------------------------------------------------------------------------
 * Software versions.
 */

/**
 * @brief Get the Functionality Level (FLEVEL).
 *
 * @return unsigned int The FLEVEL.
 */
extern unsigned int cl_retflevel(void);

/**
 * @brief Get the ClamAV version string.
 *
 * E.g. clamav-0.100.0-beta
 *
 * @return const char* The version string.
 */
extern const char *cl_retver(void);

/* ----------------------------------------------------------------------------
 * Others.
 */
extern const char *cl_strerror(int clerror);

/* ----------------------------------------------------------------------------
 * Custom data scanning.
 */
struct cl_fmap;
typedef struct cl_fmap cl_fmap_t;

/**
 * @brief Read callback function type.
 *
 * A callback function pointer type for reading data from a cl_fmap_t that uses
 * reads data from a handle interface.
 *
 * Read 'count' bytes starting at 'offset' into the buffer 'buf'
 *
 * Thread safety: It is guaranteed that only one callback is executing for a
 * specific handle at any time, but there might be multiple callbacks executing
 * for different handle at the same time.
 *
 * @param handle    The handle passed to cl_fmap_open_handle, its meaning is up
 *                  to the callback's implementation
 * @param buf       A buffer to read data into, must be at least offset + count
 *                  bytes in size.
 * @param count     The number of bytes to read.
 * @param offset    The the offset into buf to read the data to. If successful,
 *                  the number of bytes actually read is returned. Upon reading
 *                  end-of-file, zero is returned. Otherwise, a -1 is returned
 *                  and the global variable errno is set to indicate the error.
 */
typedef off_t (*clcb_pread)(void* handle, void *buf, size_t count, off_t offset);

/**
 * @brief Open a map given a handle.
 *
 * Open a map for scanning custom data accessed by a handle and pread (lseek +
 * read)-like interface. For example a WIN32 HANDLE.
 * By default fmap will use aging to discard old data, unless you tell it not
 * to.
 *
 * The handle will be passed to the callback each time.
 *
 * @param handle        A handle that may be accessed using lseek + read.
 * @param offset        Initial offset to start scanning.
 * @param len           Length of the data from the start (not the offset).
 * @param use_aging     Set to a non-zero value to enable aging.
 * @param pread_cb      A callback function to read data from the handle.
 * @return cl_fmap_t*   A map representing the handle interface.
 */
extern cl_fmap_t *cl_fmap_open_handle(void* handle, size_t offset, size_t len,
				      clcb_pread, int use_aging);

/**
 * @brief Open a map given a buffer.
 *
 * Open a map for scanning custom data, where the data is already in memory,
 * either in the form of a buffer, a memory mapped file, etc.
 * Note that the memory [start, start+len) must be the _entire_ file,
 * you can't give it parts of a file and expect detection to work.
 *
 * @param start         Pointer to a buffer of data.
 * @param len           Length in bytes of the data.
 * @return cl_fmap_t*   A map representing the buffer.
 */
extern cl_fmap_t *cl_fmap_open_memory(const void *start, size_t len);

/**
 * @brief Releases resources associated with the map.
 *
 * You should release any resources you hold only after (handles, maps) calling
 * this function.
 *
 * @param map           Map to be closed.
 */
extern void cl_fmap_close(cl_fmap_t*);

/**
 * @brief Scan custom data.
 *
 * @param map           Buffer to be scanned, in form of a cl_fmap_t.
 * @param filename      Name of data origin. Does not need to be an actual
 *                      file on disk. May be NULL if a name is not available.
 * @param[out] virname  Pointer to receive the signature match name name if a
 *                      signature matched.
 * @param[out] scanned  Number of bytes scanned.
 * @param engine        The scanning engine.
 * @param scanoptions   The scanning options struct.
 * @param context       An application-defined context struct, opaque to
 *                      libclamav. May be used within your callback functions.
 * @return cl_error_t   CL_CLEAN if no signature matched. CL_VIRUS if a
 *                      signature matched. Another CL_E* error code if an
 *                      error occured.
 */
extern int cl_scanmap_callback(cl_fmap_t *map, const char *filename, const char **virname, unsigned long int *scanned, const struct cl_engine *engine, struct cl_scan_options *scanoptions, void *context);

/* ----------------------------------------------------------------------------
 * Crypto/hashing functions
 */
#define MD5_HASH_SIZE 16
#define SHA1_HASH_SIZE 20
#define SHA256_HASH_SIZE 32
#define SHA384_HASH_SIZE 48
#define SHA512_HASH_SIZE 64

/**
 * @brief Generate a hash of data.
 *
 * @param alg       The hashing algorithm to use.
 * @param buf       The data to be hashed.
 * @param len       The length of the to-be-hashed data.
 * @param[out] obuf (optional) A buffer to store the generated hash. Use NULL to dynamically allocate buffer.
 * @param[out] olen (optional) A pointer that stores how long the generated hash is.
 * @return          A pointer to the generated hash or obuf if obuf is not NULL.
 */
unsigned char *cl_hash_data(const char *alg, const void *buf, size_t len, unsigned char *obuf, unsigned int *olen);

/**
 * @brief Generate a hash of a file.
 *
 * @param ctx       A pointer to the OpenSSL EVP_MD_CTX object.
 * @param fd        The file descriptor.
 * @param[out] olen (optional) The length of the generated hash.
 * @return          A pointer to a malloc'd buffer that holds the generated hash.
 */
unsigned char *cl_hash_file_fd_ctx(EVP_MD_CTX *ctx, int fd, unsigned int *olen);

/**
 * @brief Generate a hash of a file.
 *
 * @param fd        The file descriptor.
 * @param alg       The hashing algorithm to use.
 * @param[out] olen (optional) The length of the generated hash.
 * @return          A pointer to a malloc'd buffer that holds the generated hash.
 */
unsigned char *cl_hash_file_fd(int fd, const char *alg, unsigned int *olen);

/**
 * @brief Generate a hash of a file.
 *
 * @param fp        A pointer to a FILE object.
 * @param alg       The hashing algorithm to use.
 * @param[out] olen (optional) The length of the generated hash.
 * @return          A pointer to a malloc'd buffer that holds the generated hash.
 */
unsigned char *cl_hash_file_fp(FILE *fp, const char *alg, unsigned int *olen);

/**
 * @brief Generate a sha256 hash of data.
 *
 * @param buf       The data to hash.
 * @param len       The length of the to-be-hashed data.
 * @param[out] obuf (optional) A pointer to store the generated hash. Use NULL to dynamically allocate buffer.
 * @param[out] olen (optional) The length of the generated hash.
 * @return          A pointer to a malloc'd buffer that holds the generated hash.
 */
unsigned char *cl_sha256(const void *buf, size_t len, unsigned char *obuf, unsigned int *olen);

/**
 * @brief Generate a sha384 hash of data.
 *
 * @param buf       The data to hash.
 * @param len       The length of the to-be-hashed data.
 * @param[out] obuf (optional) A pointer to store the generated hash. Use NULL to dynamically allocate buffer.
 * @param[out] olen (optional) The length of the generated hash.
 * @return          A pointer to a malloc'd buffer that holds the generated hash.
 */
unsigned char *cl_sha384(const void *buf, size_t len, unsigned char *obuf, unsigned int *olen);

/**
 * @brief Generate a sha512 hash of data.
 *
 * @param buf       The data to hash.
 * @param len       The length of the to-be-hashed data.
 * @param[out] obuf (optional) A pointer to store the generated hash. Use NULL to dynamically allocate buffer.
 * @param[out] olen (optional) The length of the generated hash.
 * @return          A pointer to a malloc'd buffer that holds the generated hash.
 */
unsigned char *cl_sha512(const void *buf, size_t len, unsigned char *obuf, unsigned int *olen);

/**
 * @brief Generate a sha1 hash of data.
 *
 * @param buf       The data to hash.
 * @param len       The length of the to-be-hashed data.
 * @param[out] obuf (optional) A pointer to store the generated hash. Use NULL to dynamically allocate buffer.
 * @param[out] olen (optional) The length of the generated hash.
 * @return          A pointer to a malloc'd buffer that holds the generated hash.
 */
unsigned char *cl_sha1(const void *buf, size_t len, unsigned char *obuf, unsigned int *olen);

/**
 * @brief Verify validity of signed data.
 *
 * @param pkey      The public key of the keypair that signed the data.
 * @param alg       The algorithm used to hash the data.
 * @param sig       The signature block.
 * @param siglen    The length of the signature.
 * @param data      The data that was signed.
 * @param datalen   The length of the data.
 * @param decode    Whether or not to base64-decode the signature prior to verification. 1 for yes, 0 for no.
 * @return          0 for success, -1 for error or invalid signature.
 */
int cl_verify_signature(EVP_PKEY *pkey, const char *alg, unsigned char *sig, unsigned int siglen, unsigned char *data, size_t datalen, int decode);

/**
 * @brief Verify validity of signed data.
 *
 * @param pkey      The public key of the keypair that signed the data.
 * @param alg       The algorithm used to hash the data.
 * @param sig       The signature block.
 * @param siglen    The length of the signature.
 * @param digest    The hash of the signed data.
 * @return          0 for success, -1 for error or invalid signature.
 */
int cl_verify_signature_hash(EVP_PKEY *pkey, const char *alg, unsigned char *sig, unsigned int siglen, unsigned char *digest);

/**
 * @brief Verify validity of signed data.
 *
 * @param pkey      The public key of the keypair that signed the data.
 * @param alg       The algorithm used to hash the data.
 * @param sig       The signature block.
 * @param siglen    The length of the signature.
 * @param fd        The file descriptor.
 * @return          0 for success, -1 for error or invalid signature.
 */
int cl_verify_signature_fd(EVP_PKEY *pkey, const char *alg, unsigned char *sig, unsigned int siglen, int fd);

/**
 * @brief Verify validity of signed data.
 *
 * @param x509path  The path to the public key of the keypair that signed the data.
 * @param alg       The algorithm used to hash the data.
 * @param sig       The signature block.
 * @param siglen    The length of the signature.
 * @param digest    The hash of the signed data.
 * @return          0 for success, -1 for error or invalid signature.
 */
int cl_verify_signature_hash_x509_keyfile(char *x509path, const char *alg, unsigned char *sig, unsigned int siglen, unsigned char *digest);

/**
 * @brief Verify validity of signed data.
 *
 * @param x509path  The path to the public key of the keypair that signed the data.
 * @param alg       The algorithm used to hash the data.
 * @param sig       The signature block.
 * @param siglen    The length of the signature.
 * @param fd        The file descriptor.
 * @return          0 for success, -1 for error or invalid signature.
 */
int cl_verify_signature_fd_x509_keyfile(char *x509path, const char *alg, unsigned char *sig, unsigned int siglen, int fd);

/**
 * @brief Verify validity of signed data.
 *
 * @param x509path  The path to the public key of the keypair that signed the data.
 * @param alg       The algorithm used to hash the data.
 * @param sig       The signature block.
 * @param siglen    The length of the signature.
 * @param data      The data that was signed.
 * @param datalen   The length of the data.
 * @param decode    Whether or not to base64-decode the signature prior to verification. 1 for yes, 0 for no.
 * @return          0 for success, -1 for error or invalid signature.
 */
int cl_verify_signature_x509_keyfile(char *x509path, const char *alg, unsigned char *sig, unsigned int siglen, unsigned char *data, size_t datalen, int decode);

/**
 * @brief Verify validity of signed data
 *
 * @param x509      The X509 object of the public key of the keypair that signed the data.
 * @param alg       The algorithm used to hash the data.
 * @param sig       The signature block.
 * @param siglen    The length of the signature.
 * @param digest    The hash of the signed data.
 * @return          0 for success, -1 for error or invalid signature.
 */
int cl_verify_signature_hash_x509(X509 *x509, const char *alg, unsigned char *sig, unsigned int siglen, unsigned char *digest);

/**
 * @brief Verify validity of signed data.
 *
 * @param x509      The X509 object of the public key of the keypair that signed the data.
 * @param alg       The algorithm used to hash the data.
 * @param sig       The signature block.
 * @param siglen    The length of the signature.
 * @param fd        The file descriptor.
 * @return          0 for success, -1 for error or invalid signature.
 */
int cl_verify_signature_fd_x509(X509 *x509, const char *alg, unsigned char *sig, unsigned int siglen, int fd);

/**
 * @brief Verify validity of signed data.
 *
 * @param x509      The X509 object of the public key of the keypair that signed the data.
 * @param alg       The algorithm used to hash the data.
 * @param sig       The signature block.
 * @param siglen    The length of the signature.
 * @param data      The data that was signed.
 * @param datalen   The length of the data.
 * @param decode    Whether or not to base64-decode the signature prior to verification. 1 for yes, 0 for no.
 * @return          0 for success, -1 for error or invalid signature.
 */
int cl_verify_signature_x509(X509 *x509, const char *alg, unsigned char *sig, unsigned int siglen, unsigned char *data, size_t datalen, int decode);

/**
 * @brief Get an X509 object from memory.
 *
 * @param data      A pointer to a spot in memory that contains the PEM X509 cert.
 * @param len       The length of the data.
 * @return          A pointer to the X509 object on success, NULL on error.
 */
X509 *cl_get_x509_from_mem(void *data, unsigned int len);

/**
 * @brief Validate an X509 certificate chain, with the chain being located in a directory.
 *
 * @param tsdir     The path to the trust store directory.
 * @param certpath  The path to the X509 certificate to be validated.
 * @return          0 for success, -1 for error or invalid certificate.
 */
int cl_validate_certificate_chain_ts_dir(char *tsdir, char *certpath);

/**
 * @brief Validate an X509 certificate chain with support for a CRL.
 *
 * @param authorities   A NULL-terminated array of strings that hold the path of the CA's X509 certificate.
 * @param crlpath       (optional) A path to the CRL file. NULL if no CRL.
 * @param certpath      The path to the X509 certificate to be validated.
 * @return              0 for success, -1 for error or invalid certificate.
 */
int cl_validate_certificate_chain(char **authorities, char *crlpath, char *certpath);

/**
 * @brief Load an X509 certificate from a file.
 *
 * @param certpath  The path to the X509 certificate.
 */
X509 *cl_load_cert(const char *certpath);

/**
 * @brief Parse an ASN1_TIME object.
 *
 * @param timeobj   The ASN1_TIME object.
 * @return          A pointer to a (struct tm). Adjusted for time zone and daylight savings time.
 */
struct tm *cl_ASN1_GetTimeT(ASN1_TIME *timeobj);

/**
 * @brief Load a CRL file into an X509_CRL object.
 *
 * @param file  The path to the CRL.
 * @return      A pointer to an X509_CRL object or NULL on error.
 */
X509_CRL *cl_load_crl(const char *timeobj);

/**
 * @brief Sign data with a key stored on disk.
 *
 * @param keypath   The path to the RSA private key.
 * @param alg       The hash/signature algorithm to use.
 * @param hash      The hash to sign.
 * @param[out] olen A pointer that stores the size of the signature.
 * @param           Whether or not to base64-encode the signature. 1 for yes, 0 for no.
 * @return          The generated signature.
 */
unsigned char *cl_sign_data_keyfile(char *keypath, const char *alg, unsigned char *hash, unsigned int *olen, int encode);

/**
 * @brief Sign data with an RSA private key object.
 *
 * @param pkey      The RSA private key object.
 * @param alg       The hash/signature algorithm to use.
 * @param hash      The hash to sign.
 * @param[out] olen A pointer that stores the size of the signature.
 * @param           Whether or not to base64-encode the signature. 1 for yes, 0 for no.
 * @return          The generated signature.
 */
unsigned char *cl_sign_data(EVP_PKEY *pkey, const char *alg, unsigned char *hash, unsigned int *olen, int encode);

/**
 * @brief Sign a file with an RSA private key object.
 *
 * @param fd        The file descriptor.
 * @param pkey      The RSA private key object.
 * @param alg       The hash/signature algorithm to use.
 * @param[out] olen A pointer that stores the size of the signature.
 * @param encode    Whether or not to base64-encode the signature. 1 for yes, 0 for no.
 * @return          The generated signature.
 */
unsigned char *cl_sign_file_fd(int fd, EVP_PKEY *pkey, const char *alg, unsigned int *olen, int encode);

/**
 * @brief Sign a file with an RSA private key object.
 *
 * @param fp        A pointer to a FILE object.
 * @param pkey      The RSA private key object.
 * @param alg       The hash/signature algorithm to use.
 * @param[out] olen A pointer that stores the size of the signature.
 * @param encode    Whether or not to base64-encode the signature. 1 for yes, 0 for no.
 * @return          The generated signature.
 */
unsigned char *cl_sign_file_fp(FILE *fp, EVP_PKEY *pkey, const char *alg, unsigned int *olen, int encode);

/**
 * @brief Get the Private Key stored on disk.
 *
 * @param keypath   The path on disk where the private key is stored.
 * @return          A pointer to the EVP_PKEY object that contains the private key in memory.
 */
EVP_PKEY *cl_get_pkey_file(char *keypath);

void *cl_hash_init(const char *alg);
int cl_update_hash(void *ctx, const void *data, size_t sz);
int cl_finish_hash(void *ctx, void *buf);
void cl_hash_destroy(void *ctx);

#ifdef __cplusplus
}
#endif

#endif /* __CLAMAV_H */
