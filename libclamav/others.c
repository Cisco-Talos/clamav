/*
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Tomasz Kojm, Trog
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
 *
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <stdbool.h>
#ifndef _WIN32
#include <sys/wait.h>
#include <sys/time.h>
#endif
#include <time.h>
#include <fcntl.h>
#ifdef HAVE_PWD_H
#include <pwd.h>
#endif
#include <errno.h>
#include "target.h"
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#ifdef HAVE_MALLOC_H
#include <malloc.h>
#endif

#ifdef CL_THREAD_SAFE
#include <pthread.h>
#endif

#include <libxml/parser.h>

#ifndef _WIN32
#include <dlfcn.h>
#endif

#include "clamav.h"
#include "others.h"
#include "regex/regex.h"
#include "matcher-ac.h"
#include "matcher-pcre.h"
#include "default.h"
#include "scanners.h"
#include "bytecode.h"
#include "bytecode_api_impl.h"
#include "cache.h"
#include "readdb.h"
#include "stats.h"
#include "json_api.h"
#include "mpool.h"

#ifdef _WIN32
#include "libgen.h"
#endif

#include "clamav_rust.h"

cl_unrar_error_t (*cli_unrar_open)(const char *filename, void **hArchive, char **comment, uint32_t *comment_size, uint8_t debug_flag);
cl_unrar_error_t (*cli_unrar_peek_file_header)(void *hArchive, unrar_metadata_t *file_metadata);
cl_unrar_error_t (*cli_unrar_extract_file)(void *hArchive, const char *destPath, char *outputBuffer);
cl_unrar_error_t (*cli_unrar_skip_file)(void *hArchive);
void (*cli_unrar_close)(void *hArchive);

int have_rar             = 0;
static int is_rar_inited = 0;

#define PASTE2(a, b) a #b
#define PASTE(a, b) PASTE2(a, b)

#ifdef _WIN32

static void *load_module(const char *name, const char *featurename)
{
    HMODULE rhandle = NULL;
    char modulename[512];
    size_t i;

    /*
     * For Windows, just try a standard LoadLibraryA() with each of the different possible suffixes.
     * For more information on the DLL search order, see:
     *  https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order
     */
    cli_dbgmsg("searching for %s\n", featurename);

    snprintf(modulename, sizeof(modulename), "%s%s", name, LT_MODULE_EXT);

    rhandle = LoadLibraryA(modulename);
    if (NULL == rhandle) {
        char *err = NULL;

        DWORD lasterr = GetLastError();
        if (0 < lasterr) {
            FormatMessageA(
                FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS,
                NULL,
                lasterr,
                MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                (LPTSTR)&err,
                0,
                NULL);
        }

        if (NULL == err) {
            cli_dbgmsg("Cannot LoadLibraryA %s: Unknown error - %s support unavailable\n", name, featurename);
        } else {
            cli_dbgmsg("Cannot LoadLibraryA %s: %s - %s support unavailable\n", name, err, featurename);
            LocalFree(err);
        }

        goto done;
    }

    cli_dbgmsg("%s support loaded from %s\n", featurename, modulename);

done:

    return (void *)rhandle;
}

#else

static void *load_module(const char *name, const char *featurename)
{
    static const char *suffixes[] = {
        LT_MODULE_EXT "." LIBCLAMAV_FULLVER,
        PASTE(LT_MODULE_EXT ".", LIBCLAMAV_MAJORVER),
        LT_MODULE_EXT,
        "." LT_LIBEXT};
    void *rhandle                = NULL;
    char *tokenized_library_path = NULL;
    char *ld_library_path        = NULL;
    const char *err;

    char modulename[512];
    size_t i;

    /*
     * First try using LD_LIBRARY_PATH environment variable for the path.
     * We do this first because LD_LIBRARY_PATH is intended as an option to override the installed library path.
     *
     * We don't do this for Windows because Windows doesn't have an equivalent to LD_LIBRARY_PATH
     * and because LoadLibraryA() will search the executable's folder, which works for the unit tests.
     */
#ifdef _AIX
    ld_library_path = getenv("LIBPATH");
#else
    ld_library_path = getenv("LD_LIBRARY_PATH");
#endif
    if (NULL != ld_library_path && strlen(ld_library_path) > 0) {
#define MAX_LIBRARY_PATHS 10
        size_t token_index;
        size_t tokens_count;
        const char *tokens[MAX_LIBRARY_PATHS];

        /*
         * LD_LIBRARY_PATH may be a colon-separated list of directories.
         * Tokenize the list and try to load the library from each directory.
         */
        tokenized_library_path = strdup(ld_library_path);
        tokens_count           = cli_strtokenize(tokenized_library_path, ':', MAX_LIBRARY_PATHS, tokens);

        for (token_index = 0; token_index < tokens_count; token_index++) {
            cli_dbgmsg("searching for %s, LD_LIBRARY_PATH: %s\n", featurename, tokens[token_index]);

            for (i = 0; i < sizeof(suffixes) / sizeof(suffixes[0]); i++) {
#ifdef _AIX
                snprintf(modulename, sizeof(modulename),
                         "%s%s(%s%s.%d)",
                         name, ".a", name, LT_MODULE_EXT, LIBCLAMAV_MAJORVER);
#else
                snprintf(modulename, sizeof(modulename),
                         "%s" PATHSEP "%s%s",
                         tokens[token_index], name, suffixes[i]);
#endif
                rhandle = dlopen(modulename, RTLD_NOW);
                if (NULL != rhandle) {
                    cli_dbgmsg("%s support loaded from %s\n", featurename, modulename);
                    goto done;
                }

                cli_dbgmsg("searching for %s: %s not found\n", featurename, modulename);
            }
        }
    }

    /*
     * Search in "<prefix>/lib" checking with each of the different possible suffixes.
     */
    cli_dbgmsg("searching for %s, user-searchpath: %s\n", featurename, SEARCH_LIBDIR);

    for (i = 0; i < sizeof(suffixes) / sizeof(suffixes[0]); i++) {
#ifdef _AIX
        snprintf(modulename, sizeof(modulename),
                 "%s%s(%s%s.%d)",
                 name, ".a", name, LT_MODULE_EXT, LIBCLAMAV_MAJORVER);
#else
        snprintf(modulename, sizeof(modulename),
                 "%s" PATHSEP "%s%s",
                 SEARCH_LIBDIR, name, suffixes[i]);
#endif
        rhandle = dlopen(modulename, RTLD_NOW);
        if (NULL != rhandle) {
            cli_dbgmsg("%s support loaded from %s\n", featurename, modulename);
            goto done;
        }

        cli_dbgmsg("searching for %s: %s not found\n", featurename, modulename);
    }

    err = dlerror();
    if (NULL == err) {
        cli_dbgmsg("Cannot dlopen %s: Unknown error - %s support unavailable\n", name, featurename);
    } else {
        cli_dbgmsg("Cannot dlopen %s: %s - %s support unavailable\n", name, err, featurename);
    }

done:

    free(tokenized_library_path);

    return (void *)rhandle;
}

#endif

#ifdef _WIN32

static void *get_module_function(HMODULE handle, const char *name)
{
    void *procAddress = NULL;
    procAddress       = GetProcAddress(handle, name);
    if (NULL == procAddress) {
        char *err     = NULL;
        DWORD lasterr = GetLastError();
        if (0 < lasterr) {
            FormatMessageA(
                FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS,
                NULL,
                lasterr,
                MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                (LPSTR)&err,
                0,
                NULL);
        }
        if (NULL == err) {
            cli_warnmsg("Failed to get function \"%s\": Unknown error.\n", name);
        } else {
            cli_warnmsg("Failed to get function \"%s\": %s\n", name, err);
            LocalFree(err);
        }
    }
    return procAddress;
}

#else  // !_WIN32

static void *get_module_function(void *handle, const char *name)
{
    void *procAddress = NULL;
    procAddress       = dlsym(handle, name);
    if (NULL == procAddress) {
        const char *err = dlerror();
        if (NULL == err) {
            cli_warnmsg("Failed to get function \"%s\": Unknown error.\n", name);
        } else {
            cli_warnmsg("Failed to get function \"%s\": %s\n", name, err);
        }
    }
    return procAddress;
}
#endif // !_WIN32

static void rarload(void)
{
#ifndef UNRAR_LINKED
#ifdef _WIN32
    HMODULE rhandle = NULL;
#else
    void *rhandle = NULL;
#endif
#endif

    if (is_rar_inited) return;
    is_rar_inited = 1;

    if (have_rar) return;

#ifdef UNRAR_LINKED
    cli_unrar_open             = unrar_open;
    cli_unrar_peek_file_header = unrar_peek_file_header;
    cli_unrar_extract_file     = unrar_extract_file;
    cli_unrar_skip_file        = unrar_skip_file;
    cli_unrar_close            = unrar_close;
#else
    rhandle = load_module("libclamunrar_iface", "unrar");
    if (NULL == rhandle)
        return;

    if ((NULL == (cli_unrar_open = (cl_unrar_error_t (*)(const char *, void **, char **, uint32_t *, uint8_t))get_module_function(rhandle, "libclamunrar_iface_LTX_unrar_open"))) ||
        (NULL == (cli_unrar_peek_file_header = (cl_unrar_error_t (*)(void *, unrar_metadata_t *))get_module_function(rhandle, "libclamunrar_iface_LTX_unrar_peek_file_header"))) ||
        (NULL == (cli_unrar_extract_file = (cl_unrar_error_t (*)(void *, const char *, char *))get_module_function(rhandle, "libclamunrar_iface_LTX_unrar_extract_file"))) ||
        (NULL == (cli_unrar_skip_file = (cl_unrar_error_t (*)(void *))get_module_function(rhandle, "libclamunrar_iface_LTX_unrar_skip_file"))) ||
        (NULL == (cli_unrar_close = (void (*)(void *))get_module_function(rhandle, "libclamunrar_iface_LTX_unrar_close")))) {

        cli_warnmsg("Failed to load function from UnRAR module\n");
        cli_warnmsg("Version mismatch?\n");
        cli_warnmsg("UnRAR support unavailable\n");
        return;
    }
#endif

    have_rar = 1;
}

void cl_debug(void)
{
    cli_debug_flag = 1;
}

void cl_always_gen_section_hash(void)
{
    cli_always_gen_section_hash = 1;
}

unsigned int cl_retflevel(void)
{
    return CL_FLEVEL;
}

const char *cl_strerror(cl_error_t clerror)
{
    switch (clerror) {
        /* libclamav specific codes */
        case CL_CLEAN:
            return "No viruses detected";
        case CL_VIRUS:
            return "Virus(es) detected";
        case CL_ENULLARG:
            return "Null argument passed to function";
        case CL_EARG:
            return "Invalid argument passed to function";
        case CL_EMALFDB:
            return "Malformed database";
        case CL_ECVD:
            return "Broken or not a CVD file";
        case CL_EVERIFY:
            return "Can't verify database integrity";
        case CL_EUNPACK:
            return "Can't unpack some data";
        case CL_EPARSE: /* like CL_EFORMAT but reported outside magicscan() */
            return "Can't parse data";

        /* I/O and memory errors */
        case CL_EOPEN:
            return "Can't open file or directory";
        case CL_ECREAT:
            return "Can't create new file";
        case CL_EUNLINK:
            return "Can't unlink file";
        case CL_ESTAT:
            return "Can't get file status";
        case CL_EREAD:
            return "Can't read file";
        case CL_ESEEK:
            return "Can't set file offset";
        case CL_EWRITE:
            return "Can't write to file";
        case CL_EDUP:
            return "Can't duplicate file descriptor";
        case CL_EACCES:
            return "Can't access file";
        case CL_ETMPFILE:
            return "Can't create temporary file";
        case CL_ETMPDIR:
            return "Can't create temporary directory";
        case CL_EMAP:
            return "Can't map file into memory";
        case CL_EMEM:
            return "Can't allocate memory";
        case CL_ETIMEOUT:
            return "Exceeded time limit";
        /* internal (needed for debug messages) */
        case CL_BREAK:
            return "Process aborted";
        case CL_EMAXREC:
            return "Exceeded max recursion depth";
        case CL_EMAXSIZE:
            return "Exceeded max scan size";
        case CL_EMAXFILES:
            return "Exceeded max scan files";
        case CL_EFORMAT:
            return "Bad format or broken data";
        case CL_EBYTECODE:
            return "Error during bytecode execution";
        case CL_EBYTECODE_TESTFAIL:
            return "Failure in bytecode testmode";
        case CL_ELOCK:
            return "Mutex lock failed";
        case CL_EBUSY:
            return "Scanner still active";
        case CL_ESTATE:
            return "Bad state (engine not initialized, or already initialized)";
        case CL_VERIFIED:
            return "The scanned object was verified and deemed trusted";
        case CL_ERROR:
            return "Unspecified error";
        default:
            return "Unknown error code";
    }
}

cl_error_t cl_init(unsigned int initoptions)
{
    cl_error_t rc;
    struct timeval tv;
    unsigned int pid = (unsigned int)getpid();

    UNUSEDPARAM(initoptions);

    /* Rust logging initialization */
    if (!clrs_log_init()) {
        cli_dbgmsg("Unexpected problem occurred while setting up rust logging... continuing without rust logging. \
                    Please submit an issue to https://github.com/Cisco-Talos/clamav");
    }

    cl_initialize_crypto();

    rarload();

    gettimeofday(&tv, (struct timezone *)0);
    srand(pid + tv.tv_usec * (pid + 1) + clock());
    rc = bytecode_init();
    if (rc)
        return rc;

    xmlInitParser();

    return CL_SUCCESS;
}

struct cl_engine *cl_engine_new(void)
{
    cl_error_t status = CL_ERROR;

    struct cl_engine *new = NULL;
    cli_intel_t *intel    = NULL;
    char *cvdcertsdir     = NULL;

    new = (struct cl_engine *)calloc(1, sizeof(struct cl_engine));
    if (!new) {
        cli_errmsg("cl_engine_new: Can't allocate memory for cl_engine\n");
        goto done;
    }

    /* Setup default limits */
    new->maxscantime         = CLI_DEFAULT_TIMELIMIT;
    new->maxscansize         = CLI_DEFAULT_MAXSCANSIZE;
    new->maxfilesize         = CLI_DEFAULT_MAXFILESIZE;
    new->max_recursion_level = CLI_DEFAULT_MAXRECLEVEL;
    new->maxfiles            = CLI_DEFAULT_MAXFILES;
    new->min_cc_count        = CLI_DEFAULT_MIN_CC_COUNT;
    new->min_ssn_count       = CLI_DEFAULT_MIN_SSN_COUNT;
    /* Engine Max sizes */
    new->maxembeddedpe      = CLI_DEFAULT_MAXEMBEDDEDPE;
    new->maxhtmlnormalize   = CLI_DEFAULT_MAXHTMLNORMALIZE;
    new->maxhtmlnotags      = CLI_DEFAULT_MAXHTMLNOTAGS;
    new->maxscriptnormalize = CLI_DEFAULT_MAXSCRIPTNORMALIZE;
    new->maxziptypercg      = CLI_DEFAULT_MAXZIPTYPERCG;
    new->cache_size         = CLI_DEFAULT_CACHE_SIZE;

    new->bytecode_security = CL_BYTECODE_TRUST_SIGNED;
    /* 5 seconds timeout */
    new->bytecode_timeout = 60000;
    new->bytecode_mode    = CL_BYTECODE_MODE_AUTO;
    new->refcount         = 1;
    new->ac_only          = 0;
    new->ac_mindepth      = CLI_DEFAULT_AC_MINDEPTH;
    new->ac_maxdepth      = CLI_DEFAULT_AC_MAXDEPTH;

    /* Enable FIPS limits if the linked OpenSSL library is in FIPS mode. */
#if OPENSSL_VERSION_MAJOR >= 3
    if (EVP_default_properties_is_fips_enabled(NULL)) new->engine_options |= ENGINE_OPTIONS_FIPS_LIMITS;
#else
    if (FIPS_mode()) new->engine_options |= ENGINE_OPTIONS_FIPS_LIMITS;
#endif

#ifdef USE_MPOOL
    if (!(new->mempool = mpool_create())) {
        cli_errmsg("cl_engine_new: Can't allocate memory for memory pool\n");
        goto done;
    }
#endif

    new->root = MPOOL_CALLOC(new->mempool, CLI_MTARGETS, sizeof(struct cli_matcher *));
    if (!new->root) {
        cli_errmsg("cl_engine_new: Can't allocate memory for roots\n");
        goto done;
    }

    new->dconf = cli_mpool_dconf_init(new->mempool);
    if (!new->dconf) {
        cli_errmsg("cl_engine_new: Can't initialize dynamic configuration\n");
        goto done;
    }

    new->pwdbs = MPOOL_CALLOC(new->mempool, CLI_PWDB_COUNT, sizeof(struct cli_pwdb *));
    if (!new->pwdbs) {
        cli_errmsg("cl_engine_new: Can't initialize password databases\n");
        goto done;
    }

    crtmgr_init(&(new->cmgr));
    if (crtmgr_add_roots(new, &(new->cmgr), 0)) {
        cli_errmsg("cl_engine_new: Can't initialize root certificates\n");
        goto done;
    }

    /* Set up default stats/intel gathering callbacks */
    intel = calloc(1, sizeof(cli_intel_t));
    if ((intel)) {
#ifdef CL_THREAD_SAFE
        if (pthread_mutex_init(&(intel->mutex), NULL)) {
            cli_errmsg("cli_engine_new: Cannot initialize stats gathering mutex\n");
            goto done;
        }
#endif
        intel->engine     = new;
        intel->maxsamples = STATS_MAX_SAMPLES;
        intel->maxmem     = STATS_MAX_MEM;
        intel->timeout    = 10;
        new->stats_data   = intel;
    } else {
        new->stats_data = NULL;
    }

    new->cb_stats_add_sample      = NULL;
    new->cb_stats_submit          = NULL;
    new->cb_stats_flush           = clamav_stats_flush;
    new->cb_stats_remove_sample   = clamav_stats_remove_sample;
    new->cb_stats_decrement_count = clamav_stats_decrement_count;
    new->cb_stats_get_num         = clamav_stats_get_num;
    new->cb_stats_get_size        = clamav_stats_get_size;
    new->cb_stats_get_hostid      = clamav_stats_get_hostid;

    /* Setup raw disk image max settings */
    new->maxpartitions = CLI_DEFAULT_MAXPARTITIONS;

    /* Engine max settings */
    new->maxiconspe = CLI_DEFAULT_MAXICONSPE;
    new->maxrechwp3 = CLI_DEFAULT_MAXRECHWP3;

    /* PCRE matching limitations */
    new->pcre_match_limit    = CLI_DEFAULT_PCRE_MATCH_LIMIT;
    new->pcre_recmatch_limit = CLI_DEFAULT_PCRE_RECMATCH_LIMIT;
    new->pcre_max_filesize   = CLI_DEFAULT_PCRE_MAX_FILESIZE;

#ifdef HAVE_YARA

    /* YARA */
    if (cli_yara_init(new) != CL_SUCCESS) {
        cli_errmsg("cli_engine_new: failed to initialize YARA\n");
        goto done;
    }

#endif

    // Check if the CVD_CERTS_DIR environment variable is set
    cvdcertsdir = getenv("CVD_CERTS_DIR");
    if (NULL == cvdcertsdir) {
#ifdef _WIN32
        // On Windows, CERTSDIR is NOT defined in clamav-config.h.
        // So instead we'll use the certs directory next to the module file.
        char module_path[MAX_PATH]     = "";
        char certs_directory[MAX_PATH] = "";
        char *dir;
        DWORD get_module_name_ret;

        get_module_name_ret = GetModuleFileNameA(NULL, module_path, sizeof(module_path));
        if (0 == get_module_name_ret) {
            cli_errmsg("cl_engine_new: Can't get module file name\n");
            goto done;
        }

        // Ensure null-termination before using dirname()
        module_path[sizeof(module_path) - 1] = '\0';
        dir                                  = dirname(module_path);

        // set the certs directory to be the module directory + certs
        snprintf(certs_directory, sizeof(certs_directory), "%s\\certs", dir);

        cvdcertsdir = certs_directory;
#else
        cvdcertsdir = CERTSDIR;
#endif
    }
    new->certs_directory = CLI_MPOOL_STRDUP(new->mempool, cvdcertsdir);

    status = CL_SUCCESS;
    cli_dbgmsg("Initialized %s engine\n", cl_retver());

done:
    if (CL_SUCCESS != status) {
        if (NULL != new) {
            if (NULL != new->mempool) {
                if (NULL != new->certs_directory) {
                    MPOOL_FREE(new->mempool, new->certs_directory);
                }
                if (NULL != new->pwdbs) {
                    MPOOL_FREE(new->mempool, new->pwdbs);
                }
                if (NULL != new->dconf) {
                    MPOOL_FREE(new->mempool, new->dconf);
                }
                if (NULL != new->root) {
                    MPOOL_FREE(new->mempool, new->root);
                }
#ifdef USE_MPOOL
                mpool_destroy(new->mempool);
#endif
            }
            free(new);
            new = NULL;
        }
        if (NULL != intel) {
            free(intel);
        }
    }

    return new;
}

cl_error_t cl_engine_set_num(struct cl_engine *engine, enum cl_engine_field field, long long num)
{
    cl_error_t ret;

    if (!engine)
        return CL_ENULLARG;

    /* TODO: consider adding checks and warn/errs when num overflows the
     * destination type
     */
    switch (field) {
        case CL_ENGINE_MAX_SCANSIZE:
            engine->maxscansize = num;
            break;
        case CL_ENGINE_MAX_FILESIZE:
            /* We have a limit of around 2GB (INT_MAX - 2). Enforce it here.
             *
             * TODO: Large file support is large-ly untested. Remove this restriction and test with a large set of large files of various types.
             * libclamav's integer type safety has come a long way since 2014, so it's possible we could lift this restriction, but at least one
             * of the parsers is bound to behave badly with large files. */
            if ((uint64_t)num > INT_MAX - 2) {
                if ((uint64_t)num > (uint64_t)2 * 1024 * 1024 * 1024 && num != LLONG_MAX) {
                    // If greater than 2GB, warn. If exactly at 2GB, don't hassle the user.
                    cli_warnmsg("Max file-size was set to %lld bytes. Unfortunately, scanning files greater than 2147483647 bytes (2 GiB - 1) is not supported.\n", num);
                }
                engine->maxfilesize = INT_MAX - 2;
            } else {
                engine->maxfilesize = num;
            }
            break;
        case CL_ENGINE_MAX_RECURSION:
            if (!num) {
                cli_warnmsg("MaxRecursion: the value of 0 is not allowed, using default: %u\n", CLI_DEFAULT_MAXRECLEVEL);
                engine->max_recursion_level = CLI_DEFAULT_MAXRECLEVEL;
            } else
                engine->max_recursion_level = num;
            break;
        case CL_ENGINE_MAX_FILES:
            engine->maxfiles = num;
            break;
        case CL_ENGINE_MAX_EMBEDDEDPE:
            if (num < 0) {
                cli_warnmsg("MaxEmbeddedPE: negative values are not allowed, using default: %u\n", CLI_DEFAULT_MAXEMBEDDEDPE);
                engine->maxembeddedpe = CLI_DEFAULT_MAXEMBEDDEDPE;
            } else
                engine->maxembeddedpe = num;
            break;
        case CL_ENGINE_MAX_HTMLNORMALIZE:
            if (num < 0) {
                cli_warnmsg("MaxHTMLNormalize: negative values are not allowed, using default: %u\n", CLI_DEFAULT_MAXHTMLNORMALIZE);
                engine->maxhtmlnormalize = CLI_DEFAULT_MAXHTMLNORMALIZE;
            } else
                engine->maxhtmlnormalize = num;
            break;
        case CL_ENGINE_MAX_HTMLNOTAGS:
            if (num < 0) {
                cli_warnmsg("MaxHTMLNoTags: negative values are not allowed, using default: %u\n", CLI_DEFAULT_MAXHTMLNOTAGS);
                engine->maxhtmlnotags = CLI_DEFAULT_MAXHTMLNOTAGS;
            } else
                engine->maxhtmlnotags = num;
            break;
        case CL_ENGINE_MAX_SCRIPTNORMALIZE:
            if (num < 0) {
                cli_warnmsg("MaxScriptNormalize: negative values are not allowed, using default: %u\n", CLI_DEFAULT_MAXSCRIPTNORMALIZE);
                engine->maxscriptnormalize = CLI_DEFAULT_MAXSCRIPTNORMALIZE;
            } else
                engine->maxscriptnormalize = num;
            break;
        case CL_ENGINE_MAX_ZIPTYPERCG:
            if (num < 0) {
                cli_warnmsg("MaxZipTypeRcg: negative values are not allowed, using default: %u\n", CLI_DEFAULT_MAXZIPTYPERCG);
                engine->maxziptypercg = CLI_DEFAULT_MAXZIPTYPERCG;
            } else
                engine->maxziptypercg = num;
            break;
        case CL_ENGINE_MIN_CC_COUNT:
            engine->min_cc_count = num;
            break;
        case CL_ENGINE_MIN_SSN_COUNT:
            engine->min_ssn_count = num;
            break;
        case CL_ENGINE_DB_OPTIONS:
        case CL_ENGINE_DB_VERSION:
        case CL_ENGINE_DB_TIME:
            cli_warnmsg("cl_engine_set_num: The field is read only\n");
            return CL_EARG;
        case CL_ENGINE_AC_ONLY:
            engine->ac_only = num;
            break;
        case CL_ENGINE_AC_MINDEPTH:
            engine->ac_mindepth = num;
            break;
        case CL_ENGINE_AC_MAXDEPTH:
            engine->ac_maxdepth = num;
            break;
        case CL_ENGINE_KEEPTMP:
            engine->keeptmp = num;
            break;
        case CL_ENGINE_TMPDIR_RECURSION:
            if (num)
                engine->engine_options |= ENGINE_OPTIONS_TMPDIR_RECURSION;
            else
                engine->engine_options &= ~(ENGINE_OPTIONS_TMPDIR_RECURSION);
            break;
        case CL_ENGINE_FORCETODISK:
            if (num)
                engine->engine_options |= ENGINE_OPTIONS_FORCE_TO_DISK;
            else
                engine->engine_options &= ~(ENGINE_OPTIONS_FORCE_TO_DISK);
            break;
        case CL_ENGINE_BYTECODE_SECURITY:
            if (engine->dboptions & CL_DB_COMPILED) {
                cli_errmsg("cl_engine_set_num: CL_ENGINE_BYTECODE_SECURITY cannot be set after engine was compiled\n");
                return CL_EARG;
            }
            engine->bytecode_security = num;
            break;
        case CL_ENGINE_BYTECODE_TIMEOUT:
            engine->bytecode_timeout = num;
            break;
        case CL_ENGINE_BYTECODE_MODE:
            if (engine->dboptions & CL_DB_COMPILED) {
                cli_errmsg("cl_engine_set_num: CL_ENGINE_BYTECODE_MODE cannot be set after engine was compiled\n");
                return CL_EARG;
            }
            if (num == CL_BYTECODE_MODE_OFF) {
                cli_errmsg("cl_engine_set_num: CL_BYTECODE_MODE_OFF is not settable, use dboptions to turn off!\n");
                return CL_EARG;
            }
            engine->bytecode_mode = num;
            if (num == CL_BYTECODE_MODE_TEST)
                cli_infomsg(NULL, "bytecode engine in test mode\n");
            break;
        case CL_ENGINE_DISABLE_CACHE:
            if (num) {
                engine->engine_options |= ENGINE_OPTIONS_DISABLE_CACHE;
            } else {
                engine->engine_options &= ~(ENGINE_OPTIONS_DISABLE_CACHE);
                if (!(engine->cache)) {
                    ret = clean_cache_init(engine);
                    if (ret != CL_SUCCESS) {
                        cli_errmsg("cl_engine_set_num: clean_cache_init failed with error %s\n", cl_strerror(ret));
                        return ret;
                    }
                }
            }
            break;
        case CL_ENGINE_CACHE_SIZE:
            if (num) {
                engine->cache_size = (uint32_t)num;
            }
            break;
        case CL_ENGINE_DISABLE_PE_STATS:
            if (num) {
                engine->engine_options |= ENGINE_OPTIONS_DISABLE_PE_STATS;
            } else {
                engine->engine_options &= ~(ENGINE_OPTIONS_DISABLE_PE_STATS);
            }
            break;
        case CL_ENGINE_STATS_TIMEOUT:
            if ((engine->stats_data)) {
                cli_intel_t *intel = (cli_intel_t *)(engine->stats_data);

                intel->timeout = (uint32_t)num;
            }
            break;
        case CL_ENGINE_MAX_PARTITIONS:
            engine->maxpartitions = (uint32_t)num;
            break;
        case CL_ENGINE_MAX_ICONSPE:
            engine->maxiconspe = (uint32_t)num;
            break;
        case CL_ENGINE_MAX_RECHWP3:
            engine->maxrechwp3 = (uint32_t)num;
            break;
        case CL_ENGINE_MAX_SCANTIME:
            engine->maxscantime = (uint32_t)num;
            break;
        case CL_ENGINE_PCRE_MATCH_LIMIT:
            engine->pcre_match_limit = (uint64_t)num;
            break;
        case CL_ENGINE_PCRE_RECMATCH_LIMIT:
            engine->pcre_recmatch_limit = (uint64_t)num;
            break;
        case CL_ENGINE_PCRE_MAX_FILESIZE:
            engine->pcre_max_filesize = (uint64_t)num;
            break;
        case CL_ENGINE_DISABLE_PE_CERTS:
            if (num) {
                engine->engine_options |= ENGINE_OPTIONS_DISABLE_PE_CERTS;
            } else {
                engine->engine_options &= ~(ENGINE_OPTIONS_DISABLE_PE_CERTS);
            }
            break;
        case CL_ENGINE_PE_DUMPCERTS:
            if (num) {
                engine->engine_options |= ENGINE_OPTIONS_PE_DUMPCERTS;
            } else {
                engine->engine_options &= ~(ENGINE_OPTIONS_PE_DUMPCERTS);
            }
            break;
        case CL_ENGINE_FIPS_LIMITS:
            if (num) {
                engine->engine_options |= ENGINE_OPTIONS_FIPS_LIMITS;
            } else {
                engine->engine_options &= ~(ENGINE_OPTIONS_FIPS_LIMITS);
            }
            break;
        default:
            cli_errmsg("cl_engine_set_num: Incorrect field number\n");
            return CL_EARG;
    }

    return CL_SUCCESS;
}

long long cl_engine_get_num(const struct cl_engine *engine, enum cl_engine_field field, int *err)
{
    if (!engine) {
        cli_errmsg("cl_engine_get_num: engine == NULL\n");
        if (err)
            *err = CL_ENULLARG;
        return -1;
    }

    if (err)
        *err = CL_SUCCESS;

    switch (field) {
        case CL_ENGINE_DB_OPTIONS:
            return engine->dboptions;
        case CL_ENGINE_MAX_SCANSIZE:
            return engine->maxscansize;
        case CL_ENGINE_MAX_FILESIZE:
            return engine->maxfilesize;
        case CL_ENGINE_MAX_RECURSION:
            return engine->max_recursion_level;
        case CL_ENGINE_MAX_FILES:
            return engine->maxfiles;
        case CL_ENGINE_MAX_EMBEDDEDPE:
            return engine->maxembeddedpe;
        case CL_ENGINE_MAX_HTMLNORMALIZE:
            return engine->maxhtmlnormalize;
        case CL_ENGINE_MAX_HTMLNOTAGS:
            return engine->maxhtmlnotags;
        case CL_ENGINE_MAX_SCRIPTNORMALIZE:
            return engine->maxscriptnormalize;
        case CL_ENGINE_MAX_ZIPTYPERCG:
            return engine->maxziptypercg;
        case CL_ENGINE_MIN_CC_COUNT:
            return engine->min_cc_count;
        case CL_ENGINE_MIN_SSN_COUNT:
            return engine->min_ssn_count;
        case CL_ENGINE_DB_VERSION:
            return engine->dbversion[0];
        case CL_ENGINE_DB_TIME:
            return engine->dbversion[1];
        case CL_ENGINE_AC_ONLY:
            return engine->ac_only;
        case CL_ENGINE_AC_MINDEPTH:
            return engine->ac_mindepth;
        case CL_ENGINE_AC_MAXDEPTH:
            return engine->ac_maxdepth;
        case CL_ENGINE_KEEPTMP:
            return engine->keeptmp;
        case CL_ENGINE_TMPDIR_RECURSION:
            return engine->engine_options & ENGINE_OPTIONS_TMPDIR_RECURSION;
        case CL_ENGINE_FORCETODISK:
            return engine->engine_options & ENGINE_OPTIONS_FORCE_TO_DISK;
        case CL_ENGINE_BYTECODE_SECURITY:
            return engine->bytecode_security;
        case CL_ENGINE_BYTECODE_TIMEOUT:
            return engine->bytecode_timeout;
        case CL_ENGINE_BYTECODE_MODE:
            return engine->bytecode_mode;
        case CL_ENGINE_DISABLE_CACHE:
            return engine->engine_options & ENGINE_OPTIONS_DISABLE_CACHE;
        case CL_ENGINE_CACHE_SIZE:
            return engine->cache_size;
        case CL_ENGINE_STATS_TIMEOUT:
            return ((cli_intel_t *)(engine->stats_data))->timeout;
        case CL_ENGINE_MAX_PARTITIONS:
            return engine->maxpartitions;
        case CL_ENGINE_MAX_ICONSPE:
            return engine->maxiconspe;
        case CL_ENGINE_MAX_RECHWP3:
            return engine->maxrechwp3;
        case CL_ENGINE_MAX_SCANTIME:
            return engine->maxscantime;
        case CL_ENGINE_PCRE_MATCH_LIMIT:
            return engine->pcre_match_limit;
        case CL_ENGINE_PCRE_RECMATCH_LIMIT:
            return engine->pcre_recmatch_limit;
        case CL_ENGINE_PCRE_MAX_FILESIZE:
            return engine->pcre_max_filesize;
        default:
            cli_errmsg("cl_engine_get: Incorrect field number\n");
            if (err)
                *err = CL_EARG;
            return -1;
    }
}

cl_error_t cl_engine_set_str(struct cl_engine *engine, enum cl_engine_field field, const char *str)
{
    if (!engine)
        return CL_ENULLARG;

    switch (field) {
        case CL_ENGINE_PUA_CATEGORIES:
            if (NULL != engine->pua_cats) {
                MPOOL_FREE(engine->mempool, engine->pua_cats);
                engine->pua_cats = NULL;
            }
            engine->pua_cats = CLI_MPOOL_STRDUP(engine->mempool, str);
            if (NULL == engine->pua_cats)
                return CL_EMEM;
            break;
        case CL_ENGINE_TMPDIR:
            if (NULL != engine->tmpdir) {
                MPOOL_FREE(engine->mempool, engine->tmpdir);
                engine->tmpdir = NULL;
            }
            engine->tmpdir = CLI_MPOOL_STRDUP(engine->mempool, str);
            if (NULL == engine->tmpdir)
                return CL_EMEM;
            break;
        case CL_ENGINE_CVDCERTSDIR:
            if (NULL != engine->certs_directory) {
                MPOOL_FREE(engine->mempool, engine->certs_directory);
                engine->certs_directory = NULL;
            }
            engine->certs_directory = CLI_MPOOL_STRDUP(engine->mempool, str);
            if (NULL == engine->certs_directory)
                return CL_EMEM;
            break;
        default:
            cli_errmsg("cl_engine_set_num: Incorrect field number\n");
            return CL_EARG;
    }

    return CL_SUCCESS;
}

const char *cl_engine_get_str(const struct cl_engine *engine, enum cl_engine_field field, int *err)
{
    if (!engine) {
        cli_errmsg("cl_engine_get_str: engine == NULL\n");
        if (err)
            *err = CL_ENULLARG;
        return NULL;
    }

    if (err)
        *err = CL_SUCCESS;

    switch (field) {
        case CL_ENGINE_PUA_CATEGORIES:
            return engine->pua_cats;
        case CL_ENGINE_TMPDIR:
            return engine->tmpdir;
        case CL_ENGINE_CVDCERTSDIR:
            return engine->certs_directory;
        default:
            cli_errmsg("cl_engine_get: Incorrect field number\n");
            if (err)
                *err = CL_EARG;
            return NULL;
    }
}

struct cl_settings *cl_engine_settings_copy(const struct cl_engine *engine)
{
    struct cl_settings *settings;

    settings = (struct cl_settings *)malloc(sizeof(struct cl_settings));
    if (!settings) {
        cli_errmsg("cl_engine_settings_copy: Unable to allocate memory for settings %llu\n",
                   (long long unsigned)sizeof(struct cl_settings));
        return NULL;
    }

    settings->ac_only             = engine->ac_only;
    settings->ac_mindepth         = engine->ac_mindepth;
    settings->ac_maxdepth         = engine->ac_maxdepth;
    settings->tmpdir              = engine->tmpdir ? strdup(engine->tmpdir) : NULL;
    settings->keeptmp             = engine->keeptmp;
    settings->maxscantime         = engine->maxscantime;
    settings->maxscansize         = engine->maxscansize;
    settings->maxfilesize         = engine->maxfilesize;
    settings->max_recursion_level = engine->max_recursion_level;
    settings->maxfiles            = engine->maxfiles;
    settings->maxembeddedpe       = engine->maxembeddedpe;
    settings->maxhtmlnormalize    = engine->maxhtmlnormalize;
    settings->maxhtmlnotags       = engine->maxhtmlnotags;
    settings->maxscriptnormalize  = engine->maxscriptnormalize;
    settings->maxziptypercg       = engine->maxziptypercg;
    settings->min_cc_count        = engine->min_cc_count;
    settings->min_ssn_count       = engine->min_ssn_count;
    settings->bytecode_security   = engine->bytecode_security;
    settings->bytecode_timeout    = engine->bytecode_timeout;
    settings->bytecode_mode       = engine->bytecode_mode;
    settings->pua_cats            = engine->pua_cats ? strdup(engine->pua_cats) : NULL;

    settings->cb_pre_cache                   = engine->cb_pre_cache;
    settings->cb_pre_scan                    = engine->cb_pre_scan;
    settings->cb_post_scan                   = engine->cb_post_scan;
    settings->cb_virus_found                 = engine->cb_virus_found;
    settings->cb_sigload                     = engine->cb_sigload;
    settings->cb_sigload_ctx                 = engine->cb_sigload_ctx;
    settings->cb_sigload_progress            = engine->cb_sigload_progress;
    settings->cb_sigload_progress_ctx        = engine->cb_sigload_progress_ctx;
    settings->cb_engine_compile_progress     = engine->cb_engine_compile_progress;
    settings->cb_engine_compile_progress_ctx = engine->cb_engine_compile_progress_ctx;
    settings->cb_engine_free_progress        = engine->cb_engine_free_progress;
    settings->cb_engine_free_progress_ctx    = engine->cb_engine_free_progress_ctx;
    settings->cb_hash                        = engine->cb_hash;
    settings->cb_meta                        = engine->cb_meta;
    settings->cb_file_props                  = engine->cb_file_props;
    settings->engine_options                 = engine->engine_options;
    settings->cache_size                     = engine->cache_size;

    settings->cb_stats_add_sample      = engine->cb_stats_add_sample;
    settings->cb_stats_remove_sample   = engine->cb_stats_remove_sample;
    settings->cb_stats_decrement_count = engine->cb_stats_decrement_count;
    settings->cb_stats_submit          = engine->cb_stats_submit;
    settings->cb_stats_flush           = engine->cb_stats_flush;
    settings->cb_stats_get_num         = engine->cb_stats_get_num;
    settings->cb_stats_get_size        = engine->cb_stats_get_size;
    settings->cb_stats_get_hostid      = engine->cb_stats_get_hostid;

    settings->maxpartitions = engine->maxpartitions;

    settings->maxiconspe = engine->maxiconspe;
    settings->maxrechwp3 = engine->maxrechwp3;

    settings->pcre_match_limit    = engine->pcre_match_limit;
    settings->pcre_recmatch_limit = engine->pcre_recmatch_limit;
    settings->pcre_max_filesize   = engine->pcre_max_filesize;

    return settings;
}

cl_error_t cl_engine_settings_apply(struct cl_engine *engine, const struct cl_settings *settings)
{
    engine->ac_only             = settings->ac_only;
    engine->ac_mindepth         = settings->ac_mindepth;
    engine->ac_maxdepth         = settings->ac_maxdepth;
    engine->keeptmp             = settings->keeptmp;
    engine->maxscantime         = settings->maxscantime;
    engine->maxscansize         = settings->maxscansize;
    engine->maxfilesize         = settings->maxfilesize;
    engine->max_recursion_level = settings->max_recursion_level;
    engine->maxfiles            = settings->maxfiles;
    engine->maxembeddedpe       = settings->maxembeddedpe;
    engine->maxhtmlnormalize    = settings->maxhtmlnormalize;
    engine->maxhtmlnotags       = settings->maxhtmlnotags;
    engine->maxscriptnormalize  = settings->maxscriptnormalize;
    engine->maxziptypercg       = settings->maxziptypercg;
    engine->min_cc_count        = settings->min_cc_count;
    engine->min_ssn_count       = settings->min_ssn_count;
    engine->bytecode_security   = settings->bytecode_security;
    engine->bytecode_timeout    = settings->bytecode_timeout;
    engine->bytecode_mode       = settings->bytecode_mode;
    engine->engine_options      = settings->engine_options;
    engine->cache_size          = settings->cache_size;

    if (engine->tmpdir)
        MPOOL_FREE(engine->mempool, engine->tmpdir);
    if (settings->tmpdir) {
        engine->tmpdir = CLI_MPOOL_STRDUP(engine->mempool, settings->tmpdir);
        if (!engine->tmpdir)
            return CL_EMEM;
    } else {
        engine->tmpdir = NULL;
    }

    if (engine->pua_cats)
        MPOOL_FREE(engine->mempool, engine->pua_cats);
    if (settings->pua_cats) {
        engine->pua_cats = CLI_MPOOL_STRDUP(engine->mempool, settings->pua_cats);
        if (!engine->pua_cats)
            return CL_EMEM;
    } else {
        engine->pua_cats = NULL;
    }

    engine->cb_pre_cache                   = settings->cb_pre_cache;
    engine->cb_pre_scan                    = settings->cb_pre_scan;
    engine->cb_post_scan                   = settings->cb_post_scan;
    engine->cb_virus_found                 = settings->cb_virus_found;
    engine->cb_sigload                     = settings->cb_sigload;
    engine->cb_sigload_ctx                 = settings->cb_sigload_ctx;
    engine->cb_sigload_progress            = settings->cb_sigload_progress;
    engine->cb_sigload_progress_ctx        = settings->cb_sigload_progress_ctx;
    engine->cb_engine_compile_progress     = settings->cb_engine_compile_progress;
    engine->cb_engine_compile_progress_ctx = settings->cb_engine_compile_progress_ctx;
    engine->cb_engine_free_progress        = settings->cb_engine_free_progress;
    engine->cb_engine_free_progress_ctx    = settings->cb_engine_free_progress_ctx;
    engine->cb_hash                        = settings->cb_hash;
    engine->cb_meta                        = settings->cb_meta;
    engine->cb_file_props                  = settings->cb_file_props;

    engine->cb_stats_add_sample      = settings->cb_stats_add_sample;
    engine->cb_stats_remove_sample   = settings->cb_stats_remove_sample;
    engine->cb_stats_decrement_count = settings->cb_stats_decrement_count;
    engine->cb_stats_submit          = settings->cb_stats_submit;
    engine->cb_stats_flush           = settings->cb_stats_flush;
    engine->cb_stats_get_num         = settings->cb_stats_get_num;
    engine->cb_stats_get_size        = settings->cb_stats_get_size;
    engine->cb_stats_get_hostid      = settings->cb_stats_get_hostid;

    engine->maxpartitions = settings->maxpartitions;

    engine->maxiconspe = settings->maxiconspe;
    engine->maxrechwp3 = settings->maxrechwp3;

    engine->pcre_match_limit    = settings->pcre_match_limit;
    engine->pcre_recmatch_limit = settings->pcre_recmatch_limit;
    engine->pcre_max_filesize   = settings->pcre_max_filesize;

    return CL_SUCCESS;
}

cl_error_t cl_engine_settings_free(struct cl_settings *settings)
{
    if (!settings)
        return CL_ENULLARG;

    free(settings->tmpdir);
    free(settings->pua_cats);
    free(settings);
    return CL_SUCCESS;
}

void cli_append_potentially_unwanted_if_heur_exceedsmax(cli_ctx *ctx, char *vname)
{
    if (!ctx->limit_exceeded) {
        ctx->limit_exceeded = true; // guard against adding an alert (or metadata) a million times for non-fatal exceeds-max conditions
                                    // TODO: consider changing this from a bool to a threshold so we could at least see more than 1 limits exceeded

        if (SCAN_HEURISTIC_EXCEEDS_MAX) {
            cli_append_potentially_unwanted(ctx, vname);
            cli_dbgmsg("%s: scanning may be incomplete and additional analysis needed for this file.\n", vname);
        }

        /* Also record the event in the scan metadata, under "ParseErrors" */
        if (SCAN_COLLECT_METADATA && ctx->this_layer_metadata_json) {
            cli_json_parse_error(ctx->this_layer_metadata_json, vname);
        }
    }
}

cl_error_t cli_checklimits(const char *who, cli_ctx *ctx, uint64_t need1, uint64_t need2, uint64_t need3)
{
    cl_error_t ret = CL_SUCCESS;
    uint64_t needed;

    if (!ctx) {
        /* if called without limits, go on, unpack, scan */
        goto done;
    }

    needed = (need1 > need2) ? need1 : need2;
    needed = (needed > need3) ? needed : need3;

    /* Enforce global time limit, if limit enabled */
    ret = cli_checktimelimit(ctx);
    if (CL_SUCCESS != ret) {
        // Exceeding the time limit will abort the scan.
        // The logic for this and the possible heuristic is done inside the cli_checktimelimit function.
        goto done;
    }

    /* Enforce global scan-size limit, if limit enabled */
    if (needed && (ctx->engine->maxscansize != 0) && (ctx->engine->maxscansize - ctx->scansize < needed)) {
        /* The size needed is greater than the remaining scansize ... Skip this file. */
        cli_dbgmsg("%s: scansize exceeded (initial: " STDu64 ", consumed: " STDu64 ", needed: " STDu64 ")\n", who, ctx->engine->maxscansize, ctx->scansize, needed);
        ret = CL_EMAXSIZE;
        cli_append_potentially_unwanted_if_heur_exceedsmax(ctx, "Heuristics.Limits.Exceeded.MaxScanSize");
        goto done;
    }

    /* Enforce per-file file-size limit, if limit enabled */
    if (needed && (ctx->engine->maxfilesize != 0) && (ctx->engine->maxfilesize < needed)) {
        /* The size needed is greater than that limit ... Skip this file. */
        cli_dbgmsg("%s: filesize exceeded (allowed: " STDu64 ", needed: " STDu64 ")\n", who, ctx->engine->maxfilesize, needed);
        ret = CL_EMAXSIZE;
        cli_append_potentially_unwanted_if_heur_exceedsmax(ctx, "Heuristics.Limits.Exceeded.MaxFileSize");
        goto done;
    }

    /* Enforce limit on number of embedded files, if limit enabled */
    if ((ctx->engine->maxfiles != 0) && (ctx->scannedfiles >= ctx->engine->maxfiles)) {
        /* This file would exceed the max # of files ... Skip this file. */
        cli_dbgmsg("%s: files limit reached (max: %u)\n", who, ctx->engine->maxfiles);
        ret = CL_EMAXFILES;
        cli_append_potentially_unwanted_if_heur_exceedsmax(ctx, "Heuristics.Limits.Exceeded.MaxFiles");

        // We don't need to set the `ctx->abort_scan` flag here.
        // We want `cli_magic_scan()` to finish scanning the current file, but not any future files.
        // We keep track of the # scanned files with `ctx->scannedfiles`, and that should be sufficient to prevent
        // additional files from being scanned.
        goto done;
    }

done:

    return ret;
}

cl_error_t cli_updatelimits(cli_ctx *ctx, size_t needed)
{
    cl_error_t ret = cli_checklimits("cli_updatelimits", ctx, needed, 0, 0);

    if (ret != CL_SUCCESS) {
        return ret;
    }

    ctx->scannedfiles++;
    ctx->scansize += needed;
    if (ctx->scansize > ctx->engine->maxscansize)
        ctx->scansize = ctx->engine->maxscansize;

    return CL_SUCCESS;
}

/**
 * @brief Check if we've exceeded the time limit.
 * If ctx is NULL, there can be no timelimit so just return success.
 *
 * @param ctx         The scanning context.
 * @return cl_error_t CL_SUCCESS if has not exceeded, CL_ETIMEOUT if has exceeded.
 */
cl_error_t cli_checktimelimit(cli_ctx *ctx)
{
    cl_error_t ret = CL_SUCCESS;

    if (NULL == ctx) {
        goto done;
    }

    if (ctx->time_limit.tv_sec != 0) {
        struct timeval now;
        if (gettimeofday(&now, NULL) == 0) {
            if ((now.tv_sec > ctx->time_limit.tv_sec) ||
                (now.tv_sec == ctx->time_limit.tv_sec && now.tv_usec > ctx->time_limit.tv_usec)) {
                ctx->abort_scan = true;
                ret             = CL_ETIMEOUT;
            }
        }
    }

    if (CL_ETIMEOUT == ret) {
        cli_append_potentially_unwanted_if_heur_exceedsmax(ctx, "Heuristics.Limits.Exceeded.MaxScanTime");

        // abort_scan flag is set so that in cli_magic_scan() we *will* stop scanning, even if we lose the status code.
        ctx->abort_scan = true;
    }

done:
    return ret;
}

char *cli_hashstream(FILE *fs, uint8_t *hash, cli_hash_type_t type)
{
    uint8_t digest[CLI_HASHLEN_MAX];
    char buff[FILEBUFF];
    char *hashstr = NULL;
    char *pt;
    size_t i, bytes;
    const char *hash_alg = NULL;
    size_t hash_len;
    void *ctx = NULL;

    if (!fs) {
        cli_errmsg("cli_hashstream: NULL file stream\n");
        goto done;
    }

    if (type < CLI_HASH_MD5 || type >= CLI_HASH_AVAIL_TYPES) {
        cli_errmsg("cli_hashstream: Unsupported hash type %d\n", type);
        goto done;
    }

    hash_alg = cli_hash_name(type);
    hash_len = cli_hash_len(type);

    ctx = cl_hash_init(hash_alg);
    if (!(ctx)) {
        cli_errmsg("cli_hashstream: Unable to initialize hash context for %s\n", hash_alg);
        goto done;
    }

    while (0 != (bytes = fread(buff, 1, FILEBUFF, fs))) {
        if (cl_update_hash(ctx, buff, bytes) != 0) {
            cli_errmsg("cli_hashstream: Failed to update hash for %s\n", hash_alg);
            goto done;
        }
    }
    cl_finish_hash(ctx, digest);
    ctx = NULL;

    if (!(hashstr = (char *)calloc(hash_len * 2 + 1, sizeof(char)))) {
        cli_errmsg("cli_hashstream: Unable to allocate memory for hash string\n");
        goto done;
    }

    pt = hashstr;
    for (i = 0; i < hash_len; i++) {
        sprintf(pt, "%02x", digest[i]);
        pt += 2;
    }

    if (hash) {
        memcpy(hash, digest, hash_len);
    }

done:
    if (ctx) {
        cl_hash_destroy(ctx);
    }

    return hashstr;
}

char *cli_hashfile(const char *filename, uint8_t *hash, cli_hash_type_t type)
{
    FILE *fs;
    char *hashstr;

    if ((fs = fopen(filename, "rb")) == NULL) {
        cli_errmsg("cli_hashfile(): Can't open file %s\n", filename);
        return NULL;
    }

    hashstr = cli_hashstream(fs, hash, type);

    fclose(fs);
    return hashstr;
}

/* Function: unlink
        unlink() with error checking
*/
cl_error_t cli_unlink(const char *pathname)
{
    if (unlink(pathname) == -1) {
#ifdef _WIN32
        /* Windows may fail to unlink a file if it is marked read-only,
         * even if the user has permissions to delete the file. */
        if (-1 == _chmod(pathname, _S_IWRITE)) {
            char err[128];
            cli_warnmsg("cli_unlink: _chmod failure for %s - %s\n", pathname, cli_strerror(errno, err, sizeof(err)));
            return CL_EUNLINK;
        } else if (unlink(pathname) == -1) {
            char err[128];
            cli_warnmsg("cli_unlink: unlink failure for %s - %s\n", pathname, cli_strerror(errno, err, sizeof(err)));
            return CL_EUNLINK;
        }
        return CL_SUCCESS;
#else
        char err[128];
        cli_warnmsg("cli_unlink: unlink failure for %s - %s\n", pathname, cli_strerror(errno, err, sizeof(err)));
        return CL_EUNLINK;
#endif
    }
    return CL_SUCCESS;
}

cl_error_t cli_virus_found_cb(cli_ctx *ctx, const char *virname, bool is_potentially_unwanted)
{
    cl_error_t status = CL_VIRUS;

    if (!ctx || !virname) {
        return CL_ENULLARG;
    }

    /* Run deprecated legacy virus callback */
    if (ctx->engine->cb_virus_found) {
        ctx->engine->cb_virus_found(
            fmap_fd(ctx->fmap),
            virname,
            ctx->cb_ctx);
    }

    /* Run the alert callback */
    status = cli_dispatch_scan_callback(ctx, CL_SCAN_CALLBACK_ALERT);

    if (CL_CLEAN == status) {
        // An alert callback returning CL_CLEAN means to ignore this alert and keep scanning.
        // We need to remove the last alerting indicator from the evidence.
        bool remove_successful;
        FFIError *remove_indicator_error = NULL;

        remove_successful = evidence_remove_indicator(
            ctx->this_layer_evidence,
            virname,
            is_potentially_unwanted ? IndicatorType_PotentiallyUnwanted : IndicatorType_Strong,
            &remove_indicator_error);
        if (!remove_successful) {
            cli_errmsg("cli_virus_found_cb: Failed to remove indicator from scan evidence: %s\n", ffierror_fmt(remove_indicator_error));
            status = CL_ERROR;
            goto done;
        }

        if (SCAN_COLLECT_METADATA && ctx->this_layer_metadata_json) {
            // Remove the last alert from the "Alerts" array.
            json_object *alerts = NULL;
            if (json_object_object_get_ex(ctx->this_layer_metadata_json, "Alerts", &alerts)) {
                int json_ret = 0;

                // Get the index of the last alert.
                size_t num_alerts = json_object_array_length(alerts);
                if (0 == num_alerts) {
                    cli_errmsg("cli_virus_found_cb: Attempting to ignore an alert, but alert not found in metadata Alerts array.\n");
                    status = CL_ERROR;
                    goto done;
                }

                // Remove the alert from the Alerts array.
                json_ret = json_object_array_del_idx(alerts, num_alerts - 1, 1);
                if (0 != json_ret) {
                    cli_errmsg("cli_virus_found_cb: Failed to remove alert from metadata JSON.\n");
                    status = CL_ERROR;
                    goto done;
                }

                // If there aren't any other alerts, we should also delete the "Alerts" array.
                if (num_alerts == 1) {
                    json_object_object_del(ctx->this_layer_metadata_json, "Alerts");
                }
            }

            // Add "Ignored" key to the last alert from the "Indicators" array.
            json_object *indicators = NULL;
            if (json_object_object_get_ex(ctx->this_layer_metadata_json, "Indicators", &indicators)) {
                int json_ret = 0;

                // Get the index of the last indicator.
                size_t num_indicators = json_object_array_length(indicators);
                if (0 == num_indicators) {
                    cli_errmsg("cli_virus_found_cb: Attempting to ignore an alert, but alert not found in metadata Alerts array.\n");
                    status = CL_ERROR;
                    goto done;
                }

                // Get the last indicator.
                json_object *indicator_obj = json_object_array_get_idx(indicators, num_indicators - 1);
                if (NULL == indicator_obj) {
                    cli_errmsg("cli_virus_found_cb: Failed to get last indicator from Indicators array.\n");
                    status = CL_ERROR;
                    goto done;
                }

                // Add an "Ignored" string to the indicator object.
                json_object *ignored = json_object_new_string("Signature ignored by alert application callback");
                if (!ignored) {
                    cli_errmsg("cli_virus_found_cb: no memory for json ignored indicator object\n");
                    status = CL_EMEM;
                    goto done;
                }
                json_ret = json_object_object_add(indicator_obj, "Ignored", ignored);
                if (0 != json_ret) {
                    cli_errmsg("cli_virus_found_cb: Failed to add Ignored boolean to indicator object\n");
                    status = CL_ERROR;
                    goto done;
                }
            }
        }
    }

done:
    return status;
}

/**
 * @brief Add an indicator to the scan evidence.
 *
 * @param ctx
 * @param virname Name of the indicator
 * @param type Type of the indicator
 * @return Returns CL_SUCCESS if added and IS in ALLMATCH mode, or if was PUA and not in HEURISTIC-PRECEDENCE-mode.
 * @return Returns CL_VIRUS if added and NOT in ALLMATCH mode, or if was PUA and not in ALLMATCH but IS in HEURISTIC-PRECEDENCE-mode.
 * @return Returns some other error code like CL_ERROR or CL_EMEM if something went wrong.
 */
static cl_error_t append_virus(cli_ctx *ctx, const char *virname, IndicatorType type)
{
    cl_error_t status             = CL_ERROR;
    cl_error_t callback_ret       = CL_VIRUS;
    FFIError *add_indicator_error = NULL;
    bool add_successful;
    char *location = NULL;

    if (NULL == ctx->recursion_stack[ctx->recursion_level].evidence) {
        // evidence storage for this layer not initialized, initialize a new evidence store.
        ctx->recursion_stack[ctx->recursion_level].evidence = evidence_new();
        if (NULL == ctx->recursion_stack[ctx->recursion_level].evidence) {
            cli_errmsg("append_virus: no memory for evidence store\n");
            status = CL_EMEM;
            goto done;
        }
    }
    ctx->this_layer_evidence = ctx->recursion_stack[ctx->recursion_level].evidence;

    add_successful = evidence_add_indicator(
        ctx->this_layer_evidence,
        virname,
        type,
        ctx->recursion_stack[ctx->recursion_level].object_id,
        &add_indicator_error);
    if (!add_successful) {
        cli_errmsg("Failed to add indicator to scan evidence: %s\n", ffierror_fmt(add_indicator_error));
        status = CL_ERROR;
        goto done;
    }

    if (SCAN_COLLECT_METADATA && ctx->this_layer_metadata_json) {
        // Add the indicator to the metadata.
        json_object *indicators = NULL;
        if (!json_object_object_get_ex(ctx->this_layer_metadata_json, "Indicators", &indicators)) {
            indicators = json_object_new_array();
            if (NULL == indicators) {
                cli_errmsg("append_virus: no memory for json Indicators array\n");
            } else {
                json_object_object_add(ctx->this_layer_metadata_json, "Indicators", indicators);
            }
        }

        // Create json object containing name, type, depth, and object_id
        json_object *indicator_obj = json_object_new_object();
        if (NULL == indicator_obj) {
            cli_errmsg("append_virus: no memory for json indicator object\n");
        } else {
            (void)json_object_object_add(indicator_obj, "Name", json_object_new_string(virname));
            switch (type) {
                case IndicatorType_Strong: {
                    (void)json_object_object_add(indicator_obj, "Type", json_object_new_string("Strong"));
                } break;
                case IndicatorType_PotentiallyUnwanted: {
                    (void)json_object_object_add(indicator_obj, "Type", json_object_new_string("PotentiallyUnwanted"));
                } break;
                case IndicatorType_Weak: {
                    (void)json_object_object_add(indicator_obj, "Type", json_object_new_string("Weak"));
                } break;
            }
            (void)json_object_object_add(indicator_obj, "Depth", json_object_new_int(0)); // 0 for this layer
            (void)cli_jsonuint64(indicator_obj, "ObjectID", (uint64_t)ctx->recursion_stack[ctx->recursion_level].object_id);
            (void)json_object_array_add(indicators, indicator_obj);
        }

        // If this is a strong or potentially unwanted indicator, we add it to the "Alerts" array.
        if (type != IndicatorType_Weak) {
            json_object *arrobj = NULL;
            if (!json_object_object_get_ex(ctx->this_layer_metadata_json, "Alerts", &arrobj)) {
                arrobj = json_object_new_array();
                if (NULL == arrobj) {
                    cli_errmsg("append_virus: no memory for json virus array\n");
                    status = CL_EMEM;
                    goto done;
                }
                (void)json_object_object_add(ctx->this_layer_metadata_json, "Alerts", arrobj);
            }

            // Increment the indicator_obj reference count, so that it can be added to the "Alerts" array.
            (void)json_object_get(indicator_obj);

            // Add the same indicator object to the "Alerts" array.
            (void)json_object_array_add(arrobj, indicator_obj);
        }
    }

    // Check for false positive hash signature matches for the current and parent layers.
    // Do this after running the virus callback, so that the callback always gets called.
    // Also do this after adding metadata, so that the metadata will correctly show ignored alerts.
    if (ctx->fmap != NULL) {
        // Check for ctx->fmap is because `do_phishing_test()` in the `check_regex.c` unit tests
        // calls append_virus() through cli_append_potentially_unwanted() without actually providing
        // an fmap.
        // TODO: Add a basic fmap for unit tests since it makes no sense to append alerts when your scan
        //       context doesn't even have an fmap.

        status = cli_check_fp(ctx, virname);
        if (CL_VERIFIED == status) {
            // FP signature found for one of the layers. Ignore indicator.
            goto done;
        }
    }

    if (type == IndicatorType_Strong) {
        // Run the virus callbacks which in clamscan says "<signature name> FOUND"
        callback_ret = cli_virus_found_cb(ctx, virname, type);

        switch (callback_ret) {
            case CL_SUCCESS:
            case CL_VERIFIED: {
                /* Caller says this thing is clean! */
                status = callback_ret;
                goto done;
            }
            default: {
                /*
                 * Keep this alert!
                 * In case of CL_BREAK, we'll handle it after we add metadata.
                 */
                break;
            }
        }

        // Set the verdict
        ctx->recursion_stack[ctx->recursion_level].verdict = CL_VERDICT_STRONG_INDICATOR;
        cli_dbgmsg("append_virus: Strong indicator '%s' added to evidence\n", virname);
    } else if (type == IndicatorType_PotentiallyUnwanted) {
        // Set the verdict, but don't override a strong indicator verdict.
        if (CL_VERDICT_STRONG_INDICATOR != ctx->recursion_stack[ctx->recursion_level].verdict) {
            ctx->recursion_stack[ctx->recursion_level].verdict = CL_VERDICT_POTENTIALLY_UNWANTED;
        }
        cli_dbgmsg("append_virus: Potentially Unwanted indicator '%s' added to evidence\n", virname);
    } else if (type == IndicatorType_Weak) {
        cli_dbgmsg("append_virus: Weak indicator '%s' added to evidence\n", virname);
    }

    if (callback_ret == CL_BREAK) {
        // Callback requested to break the scan.
        // Do that now that we've added the indicator to the evidence and metadata.
        status = CL_BREAK;
        goto done;
    }

    if (SCAN_ALLMATCHES) {
        // Never break.
        status = CL_SUCCESS;
    } else {
        // Usually break.
        switch (type) {
            case IndicatorType_Strong: {
                status = CL_VIRUS;
                // abort_scan flag is set so that in cli_magic_scan() we *will* stop scanning, even if we lose the status code.
                ctx->abort_scan = true;
                break;
            }
            case IndicatorType_PotentiallyUnwanted: {
                status = CL_SUCCESS;
                break;
            }
            default: {
                status = CL_SUCCESS;
            }
        }
    }

done:
    if (NULL != location) {
        free(location);
    }

    return status;
}

cl_error_t cli_append_potentially_unwanted(cli_ctx *ctx, const char *virname)
{
    if (SCAN_HEURISTIC_PRECEDENCE) {
        return append_virus(ctx, virname, IndicatorType_Strong);
    } else {
        return append_virus(ctx, virname, IndicatorType_PotentiallyUnwanted);
    }
}

cl_error_t cli_append_virus(cli_ctx *ctx, const char *virname)
{
    if ((strncmp(virname, "PUA.", 4) == 0) ||
        (strncmp(virname, "Heuristics.", 11) == 0) ||
        (strncmp(virname, "BC.Heuristics.", 14) == 0)) {
        return cli_append_potentially_unwanted(ctx, virname);
    } else if (strncmp(virname, "Weak.", 5) == 0) {
        return append_virus(ctx, virname, IndicatorType_Weak);
    } else {
        return append_virus(ctx, virname, IndicatorType_Strong);
    }
}

const char *cli_get_last_virus(const cli_ctx *ctx)
{
    if (!ctx || !ctx->this_layer_evidence) {
        return NULL;
    }

    return evidence_get_last_alert(ctx->this_layer_evidence);
}

const char *cli_get_last_virus_str(const cli_ctx *ctx)
{
    const char *ret;

    if (NULL != (ret = cli_get_last_virus(ctx))) {
        return ret;
    }

    return "";
}

cl_error_t cli_recursion_stack_push(cli_ctx *ctx, cl_fmap_t *map, cli_file_t type, bool is_new_buffer, uint32_t attributes)
{
    cl_error_t status = CL_SUCCESS;

    cli_scan_layer_t *current_layer = NULL;
    cli_scan_layer_t *new_layer     = NULL;

    char *new_temp_path = NULL;
    char *fmap_basename = NULL;

    // Check the regular limits
    if (CL_SUCCESS != (status = cli_checklimits("cli_recursion_stack_push", ctx, map->len, 0, 0))) {
        cli_dbgmsg("cli_recursion_stack_push: Some content was skipped. The scan result will not be cached.\n");
        emax_reached(ctx); // Disable caching for all recursion layers.
        goto done;
    }

    // Check the recursion limit
    if (ctx->recursion_level == ctx->recursion_stack_size - 1) {
        cli_dbgmsg("cli_recursion_stack_push: Archive recursion limit exceeded (%u, max: %u)\n", ctx->recursion_level, ctx->engine->max_recursion_level);
        cli_dbgmsg("cli_recursion_stack_push: Some content was skipped. The scan result will not be cached.\n");
        emax_reached(ctx); // Disable caching for all recursion layers.
        cli_append_potentially_unwanted_if_heur_exceedsmax(ctx, "Heuristics.Limits.Exceeded.MaxRecursion");
        status = CL_EMAXREC;
        goto done;
    }

    current_layer = &ctx->recursion_stack[ctx->recursion_level];
    ctx->recursion_level++;
    new_layer = &ctx->recursion_stack[ctx->recursion_level];

    memset(new_layer, 0, sizeof(cli_scan_layer_t));

    new_layer->fmap            = map;
    new_layer->type            = type;
    new_layer->size            = map->len;
    new_layer->parent          = current_layer;
    new_layer->recursion_level = current_layer->recursion_level + 1; // same as ctx->recursion_level

    // Keep track of if this is a new buffer or not.
    // And if not, how many layers deep we are in the same buffer.
    if (is_new_buffer) {
        // This the first layer in a new buffer, so we increment the number of buffer levels.
        // And reset the buffer fmap level (because it's now the zeroeth level in this new buffer).
        new_layer->recursion_level_buffer      = current_layer->recursion_level_buffer + 1;
        new_layer->recursion_level_buffer_fmap = 0;
    } else {
        // This another layer in the same buffer, so we increment the buffer fmap level.
        new_layer->recursion_level_buffer_fmap = current_layer->recursion_level_buffer_fmap + 1;
    }

    // Apply the requested next-layer attributes.
    //
    // Note that this is how we also keep track of normalized layers.
    // Normalized layers should be ignored when using the get_type() and get_intermediate_type()
    // functions so that signatures that specify the container or intermediates need not account
    // for normalized layers "contained in" HTML / Javascript / etc.
    new_layer->attributes = attributes;

    // If the current layer is marked "decrypted", all child-layers are also marked "decrypted".
    if (current_layer->attributes & LAYER_ATTRIBUTES_DECRYPTED) {
        new_layer->attributes |= LAYER_ATTRIBUTES_DECRYPTED;
    }

    // Assign a unique object_id to the new container.
    new_layer->object_id = ctx->object_count;
    ctx->object_count++;

    // Set the current layer's fmap to the new container's fmap.
    ctx->fmap = new_layer->fmap;

    // Skip initializing a new evidence object because we only need it if there are indicators found.
    // See append_virus()

    if (ctx->engine->engine_options & ENGINE_OPTIONS_TMPDIR_RECURSION) {
        char *parent_tmpdir = ctx->recursion_stack[ctx->recursion_level - 1].tmpdir;

        /*
         * Keep-temp enabled, so create a sub-directory to provide extraction directory recursion.
         */
        if ((NULL != ctx->fmap->name) &&
            (CL_SUCCESS == cli_basename(ctx->fmap->name, strlen(ctx->fmap->name), &fmap_basename, true /* posix_support_backslash_pathsep */))) {
            /*
             * The fmap has a name, lets include it in the new sub-directory.
             */
            new_temp_path = cli_gentemp_with_prefix(parent_tmpdir, fmap_basename);
            free(fmap_basename);
            fmap_basename = NULL;

            if (NULL == new_temp_path) {
                cli_errmsg("cli_magic_scan: Failed to generate temp directory name.\n");
                status = CL_EMEM;
                goto done;
            }
        } else {
            /*
             * The fmap has no name or we failed to get the basename.
             */
            new_temp_path = cli_gentemp(parent_tmpdir);
            if (NULL == new_temp_path) {
                cli_errmsg("cli_magic_scan: Failed to generate temp directory name.\n");
                status = CL_EMEM;
                goto done;
            }
        }

        if (mkdir(new_temp_path, 0700)) {
            cli_errmsg("cli_magic_scan: Can't create tmp sub-directory for scan: %s.\n", new_temp_path);
            status = CL_EACCES;
            goto done;
        }

        ctx->recursion_stack[ctx->recursion_level].tmpdir = new_temp_path;
        ctx->this_layer_tmpdir                            = new_temp_path;
        new_temp_path                                     = NULL; // ownership transferred to ctx->recursion_stack[ctx->recursion_level].tmpdir
    } else {
        /*
         * Keep-temp disabled, so use the parent layer's tmpdir.
         */
        char *parent_tmpdir = ctx->recursion_stack[ctx->recursion_level - 1].tmpdir;

        ctx->recursion_stack[ctx->recursion_level].tmpdir = parent_tmpdir;
        // Don't need to set ctx->this_layer_tmpdir, it is already set to the parent layer's tmpdir.
    }

    if (SCAN_COLLECT_METADATA) {
        /*
         * Create JSON object to record metadata during the scan.
         * Add this new layer's metadata JSON object to the parent layer's "ContainedObjects" array or "EmbeddedObjects" array.
         */
        json_object *arrobj;
        struct json_object *parent_object;
        struct json_object *new_object;
        const char *array_name;

        if (new_layer->attributes & LAYER_ATTRIBUTES_EMBEDDED) {
            array_name = "EmbeddedObjects";
        } else {
            array_name = "ContainedObjects";
        }

        parent_object = ctx->this_layer_metadata_json;
        if (!json_object_object_get_ex(parent_object, array_name, &arrobj)) {
            arrobj = json_object_new_array();
            if (NULL == arrobj) {
                cli_errmsg("cli_recursion_stack_push: no memory for json properties object\n");
                status = CL_EMEM;
                goto done;
            }
            json_object_object_add(parent_object, array_name, arrobj);
        }
        new_object = json_object_new_object();
        if (NULL == new_object) {
            cli_errmsg("cli_recursion_stack_push: no memory for json properties object\n");
            status = CL_EMEM;
            goto done;
        }
        json_object_array_add(arrobj, new_object);

        ctx->recursion_stack[ctx->recursion_level].metadata_json = new_object;
        ctx->this_layer_metadata_json                            = new_object;

        /*
         * Add basic file metadata to the JSON object.
         */
        if (new_layer->fmap->name) {
            status = cli_jsonstr(ctx->this_layer_metadata_json, "FileName", new_layer->fmap->name);
            if (status != CL_SUCCESS) {
                cli_errmsg("cli_recursion_stack_push: no memory for json FileName object\n");
                goto done;
            }
        }
        if (new_layer->attributes & LAYER_ATTRIBUTES_EMBEDDED) {
            /* For embedded files, we can just say it's at some offset in the parent file.
             * Offset is calculated from fmap->real_len - fmap->len */
            status = cli_jsonuint64(ctx->this_layer_metadata_json, "Offset", (uint64_t)(new_layer->fmap->real_len - new_layer->fmap->len));
            if (status != CL_SUCCESS) {
                cli_errmsg("cli_recursion_stack_push: no memory for json Offset object\n");
                goto done;
            }
            /* Add the file type as well, since embedded files are identifed by file type signatures. */
            status = cli_jsonstr(ctx->this_layer_metadata_json, "FileType", cli_ftname(new_layer->type));
            if (status != CL_SUCCESS) {
                cli_errmsg("cli_recursion_stack_push: no memory for json FileType object\n");
                goto done;
            }
        } else {
            /* For non-embedded files, there may be a file path. */
            if (new_layer->fmap->path) {
                status = cli_jsonstr(ctx->this_layer_metadata_json, "FilePath", new_layer->fmap->path);
                if (status != CL_SUCCESS) {
                    cli_errmsg("cli_recursion_stack_push: no memory for json FilePath object\n");
                    goto done;
                }
            }
        }
        status = cli_jsonuint64(ctx->this_layer_metadata_json, "FileSize", (uint64_t)new_layer->fmap->len);
        if (status != CL_SUCCESS) {
            goto done;
        }

        status = cli_jsonuint64(ctx->this_layer_metadata_json, "ObjectID", (uint64_t)new_layer->object_id);
        if (status != CL_SUCCESS) {
            goto done;
        }

        /*
         * Record layer attributes in the JSON object.
         */
        if (new_layer->attributes & LAYER_ATTRIBUTES_DECRYPTED) {
            status = cli_jsonbool(ctx->this_layer_metadata_json, "Decrypted", true);
            if (status != CL_SUCCESS) {
                cli_errmsg("cli_recursion_stack_push: no memory for json Decrypted object\n");
                goto done;
            }
        }

        if (new_layer->attributes & LAYER_ATTRIBUTES_NORMALIZED) {
            status = cli_jsonbool(ctx->this_layer_metadata_json, "Normalized", true);
            if (status != CL_SUCCESS) {
                cli_errmsg("cli_recursion_stack_push: no memory for json Normalized object\n");
                goto done;
            }
        }

        if (new_layer->attributes & LAYER_ATTRIBUTES_RETYPED) {
            status = cli_jsonbool(ctx->this_layer_metadata_json, "Retyped", true);
            if (status != CL_SUCCESS) {
                cli_errmsg("cli_recursion_stack_push: no memory for json Retyped object\n");
                goto done;
            }
        }
    }

done:

    if (new_temp_path) {
        free(new_temp_path);
    }
    if (fmap_basename) {
        free(fmap_basename);
    }

    return status;
}

/**
 * @brief Copy indicators from a child JSON object to a parent JSON object.
 *
 * Used to copy indicators and alerts from a child layer to a parent layer in the recursion stack.
 * Will increment the Depth field in the indicators to reflect the new layer depth.
 *
 * @param parent        The parent JSON object to which indicators will be added.
 * @param child         The child JSON object from which indicators will be copied.
 * @param array_name    The name of the array in the JSON object where indicators are stored (e.g., "Indicators", "Alerts").
 * @return cl_error_t   CL_SUCCESS if successful, or an error code if something went wrong.
 */
static cl_error_t json_add_child_array(json_object *parent, json_object *child, const char *array_name)
{
    cl_error_t status = CL_SUCCESS;

    json_object *child_array = NULL;

    if (0 == json_object_object_get_ex(child, array_name, &child_array)) {
        cli_dbgmsg("cli_recursion_stack_pop: no %s array in child object\n", array_name);
        status = CL_SUCCESS;
        goto done;
    }

    /*
     * Found the array. Copy each element to the parent layer and increment the field named "Depth".
     */

    /* Get the parent layer array. Create a new one if it doesn't exist */
    json_object *parent_layer_indicators = NULL;
    if (!json_object_object_get_ex(parent, array_name, &parent_layer_indicators)) {
        parent_layer_indicators = json_object_new_array();
        if (NULL == parent_layer_indicators) {
            cli_errmsg("cli_recursion_stack_pop: no memory for json Indicators array\n");
            status = CL_ERROR;
            goto done;
        }

        if (json_object_object_add(parent, array_name, parent_layer_indicators)) {
            cli_errmsg("cli_recursion_stack_pop: failed to add json Indicators array to parent object\n");
            status = CL_ERROR;
            goto done;
        }
    }

    /* Get the number of indicators in this layer */
    size_t num_indicators = json_object_array_length(child_array);
    size_t i;

    /* Copy all indicators from this layer to the parent layer */
    for (i = 0; i < num_indicators; i++) {
        json_object *indicator = json_object_array_get_idx(child_array, i);
        if (NULL == indicator) {
            cli_errmsg("cli_recursion_stack_pop: Failed to get indicator at index %zu\n", i);
            status = CL_ERROR;
            goto done;
        }

        // Check if the indicator is a valid JSON object
        if (!json_object_is_type(indicator, json_type_object)) {
            continue; // Skip non-object indicators
        }

        /* Make a new object for the copy, because we need to increment the Depth field */
        json_object *indicator_copy = json_object_new_object();
        if (NULL == indicator_copy) {
            cli_errmsg("cli_recursion_stack_pop: no memory for json indicator copy\n");
            status = CL_EMEM;
            goto done;
        }

        /* Copy the indicator's properties to the new object */
        json_object_object_foreach(indicator, key, val)
        {
            if (strcmp(key, "Depth") == 0) {
                /* Depth is a new int object with incremented value */
                json_object *new_depth = json_object_new_int(json_object_get_int(val) + 1);
                if (NULL == new_depth) {
                    cli_errmsg("cli_recursion_stack_pop: no memory for json new_depth\n");
                    status = CL_EMEM;
                    goto done;
                }
                json_object_object_add(indicator_copy, key, new_depth);
            } else {
                /* All other fields are shallow copied. Just need to increment the reference count */
                json_object_get(val);
                json_object_object_add(indicator_copy, key, val);
            }
        }

        /* Add the copied indicator to the parent layer's indicators */
        json_object_array_add(parent_layer_indicators, indicator_copy);
    }

done:
    return status;
}

cl_fmap_t *cli_recursion_stack_pop(cli_ctx *ctx)
{
    cl_fmap_t *popped_map = NULL;

    if (0 == ctx->recursion_level) {
        cli_dbgmsg("cli_recursion_stack_pop: recursion_level == 0, cannot pop off more layers!\n");
        goto done;
    }

    /* If evidence (i.e. a collection of indicators / matches) were found for the popped layer, add it to the parents evidence */
    if (ctx->recursion_stack[ctx->recursion_level].evidence) {
        /*
         * Record contained matches in the parent layer's evidence.
         */
        if (ctx->recursion_stack[ctx->recursion_level - 1].evidence == NULL) {
            evidence_t parent_evidence   = NULL;
            FFIError *new_evidence_error = NULL;

            if (!evidence_new_from_child(
                    // child
                    ctx->recursion_stack[ctx->recursion_level].evidence,
                    // new parent evidence
                    &parent_evidence,
                    ctx->recursion_stack[ctx->recursion_level].attributes & LAYER_ATTRIBUTES_NORMALIZED,
                    &new_evidence_error)) {
                cli_errmsg("Failed create evidence for parent layer given child's evidence: %s\n",
                           ffierror_fmt(new_evidence_error));
                if (NULL != new_evidence_error) {
                    ffierror_free(new_evidence_error);
                }
            }

            ctx->recursion_stack[ctx->recursion_level - 1].evidence = parent_evidence;
        } else {
            FFIError *add_evidence_error = NULL;

            if (!evidence_add_child_evidence(
                    // parent
                    ctx->recursion_stack[ctx->recursion_level - 1].evidence,
                    // child
                    ctx->recursion_stack[ctx->recursion_level].evidence,
                    ctx->recursion_stack[ctx->recursion_level].attributes & LAYER_ATTRIBUTES_NORMALIZED,
                    &add_evidence_error)) {
                cli_errmsg("Failed add child's evidence to parent's evidence: %s\n",
                           ffierror_fmt(add_evidence_error));
                if (NULL != add_evidence_error) {
                    ffierror_free(add_evidence_error);
                }
            }
        }

        evidence_free(ctx->recursion_stack[ctx->recursion_level].evidence);
        ctx->recursion_stack[ctx->recursion_level].evidence = NULL;
    }

    if (SCAN_COLLECT_METADATA) {
        /*
         * Record contained indicators and alerts in the parent layer's metadata.
         * Copy the indicators and alerts from this layer to the parent layer.
         */
        json_object *this_layer_object = ctx->recursion_stack[ctx->recursion_level].metadata_json;
        json_object *parent_object     = ctx->recursion_stack[ctx->recursion_level - 1].metadata_json;

        if (this_layer_object && parent_object) {
            cl_error_t ret;

            // Copy indicators from this layer to the parent layer.
            ret = json_add_child_array(parent_object, this_layer_object, "Indicators");
            if (CL_SUCCESS != ret) {
                cli_errmsg("cli_recursion_stack_pop: Failed to copy Indicators from child to parent: %s\n", cl_strerror(ret));
            }

            // Copy alerts from this layer to the parent layer.
            ret = json_add_child_array(parent_object, this_layer_object, "Alerts");
            if (CL_SUCCESS != ret) {
                cli_errmsg("cli_recursion_stack_pop: Failed to copy Alerts from child to parent: %s\n", cl_strerror(ret));
            }
        }
    }

    if ((ctx->engine->engine_options & ENGINE_OPTIONS_TMPDIR_RECURSION)) {
        /* Delete the layer's temporary directory.
         * Use rmdir to remove empty tmp subdirectories. If rmdir fails, it wasn't empty. */
        (void)rmdir(ctx->this_layer_tmpdir);
        /* Free the temporary directory path */
        free(ctx->this_layer_tmpdir);
    }

    /* save off the fmap to return it to the caller, in case they need it */
    popped_map = ctx->recursion_stack[ctx->recursion_level].fmap;

    /* We're done with this layer, clear it */
    memset(&ctx->recursion_stack[ctx->recursion_level], 0, sizeof(cli_scan_layer_t));
    ctx->recursion_level--;

    /* Set the ctx->fmap convenience pointer to the current layer's fmap */
    ctx->fmap = ctx->recursion_stack[ctx->recursion_level].fmap;

    /* Set the ctx->this_layer_evidence convenience pointer to the current layer's evidence */
    ctx->this_layer_evidence = ctx->recursion_stack[ctx->recursion_level].evidence;

    if ((ctx->engine->engine_options & ENGINE_OPTIONS_TMPDIR_RECURSION)) {
        /* Set the ctx->this_layer_tmpdir convenience pointer to the current layer's tmpdir */
        ctx->this_layer_tmpdir = ctx->recursion_stack[ctx->recursion_level].tmpdir;
    }

    if (SCAN_COLLECT_METADATA) {
        /* Set the ctx->this_layer_metadata_json convenience pointer to the current layer's metadata_json */
        ctx->this_layer_metadata_json = ctx->recursion_stack[ctx->recursion_level].metadata_json;
    }

done:
    return popped_map;
}

/**
 * @brief Reassign the type of the current recursion stack layer.
 *
 * This is used in two places:
 * 1. Immediately after determining the file type at the top of cli_magic_scan().
 * 2. When scanraw matches with a filetype signature designed to retype the file.
 *    TODO: Consider removing reassigning the type in this second case so that it would work the same way it does for
 *          HandlerType logical signatures. That is, by using `cli_recursion_stack_push()` with the new type.
 *
 * @param ctx  The scanning context.
 * @param type The new file type for the current recursion stack layer.
 *
 * @return CL_SUCCESS on success, or an error code on failure.
 */
cl_error_t cli_recursion_stack_change_type(cli_ctx *ctx, cli_file_t type, bool run_callback)
{
    cl_error_t status = CL_ERROR;

    if ((NULL == ctx) ||
        (NULL == ctx->recursion_stack) ||
        (ctx->recursion_level >= ctx->recursion_stack_size)) {
        cli_errmsg("cli_recursion_stack_change_type: invalid context or recursion stack\n");
        status = CL_EARG;
        goto done;
    }

    ctx->recursion_stack[ctx->recursion_level].type = type;

    if (run_callback) {
        /*
         * Run the file_type callback.
         */
        status = cli_dispatch_scan_callback(ctx, CL_SCAN_CALLBACK_FILE_TYPE);
        if (CL_SUCCESS != status) {
            goto done;
        }
    }

    // If metadata is being collected, update the type in the metadata JSON object as well.
    if (SCAN_COLLECT_METADATA && ctx->this_layer_metadata_json) {
        cl_error_t ret = cli_jsonstr(ctx->this_layer_metadata_json, "FileType", cli_ftname(type));
        if (ret != CL_SUCCESS) {
            cli_errmsg("cli_recursion_stack_change_type: failed to reassign the FileType in metadata JSON: %s\n", cl_strerror(ret));
            status = ret;
            goto done;
        }
    }

    status = CL_SUCCESS;

done:
    if (status == CL_ERROR) {
        cli_errmsg("cli_recursion_stack_change_type: failed to change type for current recursion stack layer\n");
    }

    return status;
}

/**
 * @brief Convert the desired index into the recursion stack to an actual index, excluding normalized layers.
 *
 * Accepts negative indexes, which is in fact the primary use case.
 *
 * For index:
 *  0 == the outermost (bottom) layer of the stack.
 *  1 == the first layer (probably never explicitly used).
 * -1 == the present innermost (top) layer of the stack.
 * -2 == the parent layer (or "container"). That is, the second from the top of the stack.
 *
 * @param ctx   The scanning context.
 * @param index The index (probably negative) of the layer we think we want.
 * @return int  -1 if layer doesn't exist, else the index of the desired layer in the recursion_stack
 */
static int recursion_stack_get(cli_ctx *ctx, int index)
{
    int desired_layer;
    int current_layer = (int)ctx->recursion_level;

    if (index < 0) {
        desired_layer = ctx->recursion_level + index + 1; // The +1 is so that -1 == the current layer
                                                          //               and -2 == the parent layer (the container)
    } else {
        desired_layer = index;
    }

    if (desired_layer > current_layer) {
        desired_layer = ctx->recursion_level + 1; // layer doesn't exist
        goto done;
    }

    while (current_layer >= desired_layer && current_layer > 0) {
        if (ctx->recursion_stack[current_layer].attributes & LAYER_ATTRIBUTES_NORMALIZED) {
            // The current layer is normalized, so we should step back an extra layer
            // It's okay if desired_layer goes negative.
            desired_layer--;
        }

        current_layer--;
    }

done:
    return desired_layer;
}

cli_file_t cli_recursion_stack_get_type(cli_ctx *ctx, int index)
{
    int index_ignoring_normalized_layers;

    // translate requested index into index of non-normalized layer
    index_ignoring_normalized_layers = recursion_stack_get(ctx, index);

    if (0 > index_ignoring_normalized_layers) {
        // Layer too low, does not exist.
        // Most likely we're at the top layer and there is no container. That's okay.
        return CL_TYPE_ANY;
    } else if (ctx->recursion_level < (uint32_t)index_ignoring_normalized_layers) {
        // layer too high, does not exist. This should never happen!
        return CL_TYPE_IGNORED;
    }

    return ctx->recursion_stack[index_ignoring_normalized_layers].type;
}

size_t cli_recursion_stack_get_size(cli_ctx *ctx, int index)
{
    int index_ignoring_normalized_layers;

    // translate requested index into index of non-normalized layer
    index_ignoring_normalized_layers = recursion_stack_get(ctx, index);

    if (0 > index_ignoring_normalized_layers) {
        // Layer too low, does not exist.
        // Most likely we're at the top layer and there is no container. That's okay.
        return ctx->recursion_stack[0].size;
    } else if (ctx->recursion_level < (uint32_t)index_ignoring_normalized_layers) {
        // layer too high, does not exist. This should never happen!
        return 0;
    }

    return ctx->recursion_stack[index_ignoring_normalized_layers].size;
}

#ifdef C_WINDOWS
/*
 * Windows doesn't allow you to delete a directory while it is still open
 */
int cli_rmdirs(const char *dirname)
{
    int rc;
    STATBUF statb;
    DIR *dd;
    struct dirent *dent;
    char err[128];

    if (CLAMSTAT(dirname, &statb) < 0) {
        cli_warnmsg("cli_rmdirs: Can't locate %s: %s\n", dirname, cli_strerror(errno, err, sizeof(err)));
        return -1;
    }

    if (!S_ISDIR(statb.st_mode)) {
        if (cli_unlink(dirname)) return -1;
        return 0;
    }

    if ((dd = opendir(dirname)) == NULL)
        return -1;

    rc = 0;

    while ((dent = readdir(dd)) != NULL) {
        char *path;

        if (strcmp(dent->d_name, ".") == 0)
            continue;
        if (strcmp(dent->d_name, "..") == 0)
            continue;

        path = malloc(strlen(dirname) + strlen(dent->d_name) + 2);
        if (path == NULL) {
            cli_errmsg("cli_rmdirs: Unable to allocate memory for path %u\n", strlen(dirname) + strlen(dent->d_name) + 2);
            closedir(dd);
            return -1;
        }

        sprintf(path, "%s\\%s", dirname, dent->d_name);
        rc = cli_rmdirs(path);
        free(path);
        if (rc != 0)
            break;
    }

    closedir(dd);

    if (rmdir(dirname) < 0) {
        cli_errmsg("cli_rmdirs: Can't remove temporary directory %s: %s\n", dirname, cli_strerror(errno, err, sizeof(err)));
        return -1;
    }

    return rc;
}
#else
int cli_rmdirs(const char *dirname)
{
    DIR *dd;
    struct dirent *dent;
    STATBUF maind, statbuf;
    char *path;
    char err[128];

    chmod(dirname, 0700);
    if ((dd = opendir(dirname)) != NULL) {
        while (CLAMSTAT(dirname, &maind) != -1) {
            if (!rmdir(dirname)) break;
            if (errno != ENOTEMPTY && errno != EEXIST && errno != EBADF) {
                cli_errmsg("cli_rmdirs: Can't remove temporary directory %s: %s\n", dirname, cli_strerror(errno, err, sizeof(err)));
                closedir(dd);
                return -1;
            }

            while ((dent = readdir(dd))) {
                if (dent->d_ino) {
                    if (strcmp(dent->d_name, ".") && strcmp(dent->d_name, "..")) {
                        path = malloc(strlen(dirname) + strlen(dent->d_name) + 2);
                        if (!path) {
                            cli_errmsg("cli_rmdirs: Unable to allocate memory for path %llu\n", (long long unsigned)(strlen(dirname) + strlen(dent->d_name) + 2));
                            closedir(dd);
                            return -1;
                        }

                        sprintf(path, "%s" PATHSEP "%s", dirname, dent->d_name);

                        /* stat the file */
                        if (LSTAT(path, &statbuf) != -1) {
                            if (S_ISDIR(statbuf.st_mode) && !S_ISLNK(statbuf.st_mode)) {
                                if (rmdir(path) == -1) { /* can't be deleted */
                                    if (errno == EACCES) {
                                        cli_errmsg("cli_rmdirs: Can't remove some temporary directories due to access problem.\n");
                                        closedir(dd);
                                        free(path);
                                        return -1;
                                    }
                                    if (cli_rmdirs(path)) {
                                        cli_warnmsg("cli_rmdirs: Can't remove nested directory %s\n", path);
                                        free(path);
                                        closedir(dd);
                                        return -1;
                                    }
                                }
                            } else {
                                if (cli_unlink(path)) {
                                    free(path);
                                    closedir(dd);
                                    return -1;
                                }
                            }
                        }
                        free(path);
                    }
                }
            }
            rewinddir(dd);
        }

    } else {
        return -1;
    }

    closedir(dd);
    return 0;
}
#endif

/* Implement a generic bitset, trog@clamav.net */

#define BITS_PER_CHAR (8)
#define BITSET_DEFAULT_SIZE (1024)

static unsigned long nearest_power(unsigned long num)
{
    unsigned long n = BITSET_DEFAULT_SIZE;

    while (n < num) {
        n <<= 1;
        if (n == 0) {
            return num;
        }
    }
    return n;
}

bitset_t *cli_bitset_init(void)
{
    bitset_t *bs;

    bs = malloc(sizeof(bitset_t));
    if (!bs) {
        cli_errmsg("cli_bitset_init: Unable to allocate memory for bs %llu\n", (long long unsigned)sizeof(bitset_t));
        return NULL;
    }
    bs->length = BITSET_DEFAULT_SIZE;
    bs->bitset = calloc(BITSET_DEFAULT_SIZE, 1);
    if (!bs->bitset) {
        cli_errmsg("cli_bitset_init: Unable to allocate memory for bs->bitset %u\n", BITSET_DEFAULT_SIZE);
        free(bs);
        return NULL;
    }
    return bs;
}

void cli_bitset_free(bitset_t *bs)
{
    if (!bs) {
        return;
    }
    if (bs->bitset) {
        free(bs->bitset);
    }
    free(bs);
}

static bitset_t *bitset_realloc(bitset_t *bs, unsigned long min_size)
{
    unsigned long new_length;
    unsigned char *new_bitset;

    new_length = nearest_power(min_size);
    new_bitset = (unsigned char *)cli_max_realloc(bs->bitset, new_length);
    if (!new_bitset) {
        return NULL;
    }
    bs->bitset = new_bitset;
    memset(bs->bitset + bs->length, 0, new_length - bs->length);
    bs->length = new_length;
    return bs;
}

int cli_bitset_set(bitset_t *bs, unsigned long bit_offset)
{
    unsigned long char_offset;

    char_offset = bit_offset / BITS_PER_CHAR;
    bit_offset  = bit_offset % BITS_PER_CHAR;

    if (char_offset >= bs->length) {
        bs = bitset_realloc(bs, char_offset + 1);
        if (!bs) {
            return FALSE;
        }
    }
    bs->bitset[char_offset] |= ((unsigned char)1 << bit_offset);
    return TRUE;
}

int cli_bitset_test(bitset_t *bs, unsigned long bit_offset)
{
    unsigned long char_offset;

    char_offset = bit_offset / BITS_PER_CHAR;
    bit_offset  = bit_offset % BITS_PER_CHAR;

    if (char_offset >= bs->length) {
        return FALSE;
    }
    return (bs->bitset[char_offset] & ((unsigned char)1 << bit_offset));
}

void cl_engine_set_scan_callback(struct cl_engine *engine, clcb_scan callback, cl_scan_callback_t location)
{
    switch (location) {
        case CL_SCAN_CALLBACK_PRE_HASH:
            engine->cb_scan_pre_hash = callback;
            break;
        case CL_SCAN_CALLBACK_PRE_SCAN:
            engine->cb_scan_pre_scan = callback;
            break;
        case CL_SCAN_CALLBACK_POST_SCAN:
            engine->cb_scan_post_scan = callback;
            break;
        case CL_SCAN_CALLBACK_ALERT:
            engine->cb_scan_alert = callback;
            break;
        case CL_SCAN_CALLBACK_FILE_TYPE:
            engine->cb_scan_file_type = callback;
            break;
        default:
            cli_errmsg("cl_engine_set_scan_callback: Invalid scan callback location %d\n", location);
            break;
    }
}

#define PRE_HASH_NAME "PreHash"
#define PRE_SCAN_NAME "PreScan"
#define POST_SCAN_NAME "PostScan"
#define ALERT_NAME "Alert"
#define FILE_TYPE_NAME "FileType"
static const char *callback_name(cl_scan_callback_t location)
{
    switch (location) {
        case CL_SCAN_CALLBACK_PRE_HASH:
            return "pre-hash application callback";
        case CL_SCAN_CALLBACK_PRE_SCAN:
            return "pre-scan application callback";
        case CL_SCAN_CALLBACK_POST_SCAN:
            return "post-scan application callback";
        case CL_SCAN_CALLBACK_ALERT:
            return "alert application callback";
        case CL_SCAN_CALLBACK_FILE_TYPE:
            return "file-type application callback";
        default:
            return "Unknown";
    }
}

cl_error_t cli_dispatch_scan_callback(cli_ctx *ctx, cl_scan_callback_t location)
{
    cl_error_t status = CL_ERROR;
    cl_scan_layer_t *current_layer;
    clcb_scan callback = NULL;

    if (!ctx) {
        status = CL_ENULLARG;
        goto done;
    }

    /*
     * Determine which callback to use.
     */
    switch (location) {
        case CL_SCAN_CALLBACK_PRE_HASH:
            callback = ctx->engine->cb_scan_pre_hash;
            break;
        case CL_SCAN_CALLBACK_PRE_SCAN:
            callback = ctx->engine->cb_scan_pre_scan;
            break;
        case CL_SCAN_CALLBACK_POST_SCAN:
            callback = ctx->engine->cb_scan_post_scan;
            break;
        case CL_SCAN_CALLBACK_ALERT:
            callback = ctx->engine->cb_scan_alert;
            break;
        case CL_SCAN_CALLBACK_FILE_TYPE:
            callback = ctx->engine->cb_scan_file_type;
            break;
        default:
            status = CL_EARG;
            cli_errmsg("dispatch_scan_callback: Invalid callback location\n");
            goto done;
    }

    if (NULL == callback) {
        /*
         * Callback is not set.
         */
        if (location == CL_SCAN_CALLBACK_ALERT) {
            // Accept the alert.
            status = CL_VIRUS;
        } else {
            // Keep scanning.
            status = CL_SUCCESS;
        }
        goto done;
    }

    current_layer = (cl_scan_layer_t *)&ctx->recursion_stack[ctx->recursion_level];

    /*
     * Call the callback function.
     */
    // TODO: Add performance measurements around the new callback specific to each callback location.
    // perf_start(ctx, PERFT_PRECB);
    status = callback(
        current_layer, // current scan layer
        ctx->cb_ctx    // application context
    );
    // perf_stop(ctx, PERFT_PRECB);

    /*
     * Interpret the return code from the callback.
     */
    switch (status) {
        case CL_BREAK: {
            cli_dbgmsg("dispatch_scan_callback: scan aborted by callback\n");
            ctx->abort_scan = true;
        } break;

        case CL_SUCCESS /* aka CL_CLEAN */: {
            // An alert callback returning CL_SUCCESS/CL_CLEAN means to ignore this alert and keep scanning.
            // Other scan callbacks returning CL_SUCCESS means to keep scanning.
            // Regardless, we return CL_SUCCESS here. The calling function will decide what to do next.
            status = CL_SUCCESS;
        } break;

        case CL_VIRUS: {
            // Other scan callbacks returning CL_VIRUS the application wants to alert on the file.
            switch (location) {
                case CL_SCAN_CALLBACK_PRE_HASH:
                    status = cli_append_virus(ctx, "Detected.By.Callback." PRE_HASH_NAME);
                    cli_dbgmsg("dispatch_scan_callback: Detected.By.Callback." PRE_HASH_NAME " alert added by callback\n");
                    break;
                case CL_SCAN_CALLBACK_PRE_SCAN:
                    status = cli_append_virus(ctx, "Detected.By.Callback." PRE_SCAN_NAME);
                    cli_dbgmsg("dispatch_scan_callback: Detected.By.Callback." PRE_SCAN_NAME " alert added by callback\n");
                    break;
                case CL_SCAN_CALLBACK_POST_SCAN:
                    status = cli_append_virus(ctx, "Detected.By.Callback." POST_SCAN_NAME);
                    cli_dbgmsg("dispatch_scan_callback: Detected.By.Callback." POST_SCAN_NAME " alert added by callback\n");
                    break;
                case CL_SCAN_CALLBACK_ALERT:
                    // An alert callback returning CL_VIRUS means to accept the alert.
                    break;
                case CL_SCAN_CALLBACK_FILE_TYPE:
                    status = cli_append_virus(ctx, "Detected.By.Callback." FILE_TYPE_NAME);
                    cli_dbgmsg("dispatch_scan_callback: Detected.By.Callback." FILE_TYPE_NAME " alert added by callback\n");
                    break;
            }
        } break;

        case CL_VERIFIED: {
            // An alert callback returning CL_VERIFIED means the application verified the current layer as clean.
            // So we need to remove any alerts for this layer and return CL_VERIFIED (will stop scanning this layer).
            cli_dbgmsg("dispatch_scan_callback: Layer trusted by callback\n");

            // Remove any evidence for this layer and set the verdict to trusted.
            (void)cli_trust_this_layer(ctx, callback_name(location));
            status = CL_VERIFIED;
        } break;

        default: {
            cli_warnmsg("dispatch_scan_callback: Ignoring bad return code from callback\n");
            if (location == CL_SCAN_CALLBACK_ALERT) {
                // Accept the alert.
                status = CL_VIRUS;
            } else {
                // Keep scanning.
                status = CL_SUCCESS;
            }
        }
    }

done:

    return status;
}

void cl_engine_set_clcb_pre_cache(struct cl_engine *engine, clcb_pre_cache callback)
{
    engine->cb_pre_cache = callback;
}

void cl_engine_set_clcb_file_inspection(struct cl_engine *engine, clcb_file_inspection callback)
{
    engine->cb_file_inspection = callback;
}

void cl_engine_set_clcb_pre_scan(struct cl_engine *engine, clcb_pre_scan callback)
{
    engine->cb_pre_scan = callback;
}

void cl_engine_set_clcb_post_scan(struct cl_engine *engine, clcb_post_scan callback)
{
    engine->cb_post_scan = callback;
}

void cl_engine_set_clcb_virus_found(struct cl_engine *engine, clcb_virus_found callback)
{
    engine->cb_virus_found = callback;
}

void cl_engine_set_clcb_sigload(struct cl_engine *engine, clcb_sigload callback, void *context)
{
    engine->cb_sigload     = callback;
    engine->cb_sigload_ctx = callback ? context : NULL;
}

void cl_engine_set_clcb_sigload_progress(struct cl_engine *engine, clcb_progress callback, void *context)
{
    engine->cb_sigload_progress     = callback;
    engine->cb_sigload_progress_ctx = callback ? context : NULL;
}

void cl_engine_set_clcb_engine_compile_progress(struct cl_engine *engine, clcb_progress callback, void *context)
{
    engine->cb_engine_compile_progress     = callback;
    engine->cb_engine_compile_progress_ctx = callback ? context : NULL;
}

void cl_engine_set_clcb_engine_free_progress(struct cl_engine *engine, clcb_progress callback, void *context)
{
    engine->cb_engine_free_progress     = callback;
    engine->cb_engine_free_progress_ctx = callback ? context : NULL;
}

void cl_engine_set_clcb_hash(struct cl_engine *engine, clcb_hash callback)
{
    engine->cb_hash = callback;
}

void cl_engine_set_clcb_meta(struct cl_engine *engine, clcb_meta callback)
{
    engine->cb_meta = callback;
}

void cl_engine_set_clcb_file_props(struct cl_engine *engine, clcb_file_props callback)
{
    engine->cb_file_props = callback;
}

void cl_engine_set_clcb_vba(struct cl_engine *engine, clcb_generic_data callback)
{
    engine->cb_vba = callback;
}

uint8_t cli_get_debug_flag()
{
    return cli_debug_flag;
}

uint8_t cli_set_debug_flag(uint8_t debug_flag)
{
    uint8_t was    = cli_debug_flag;
    cli_debug_flag = debug_flag;

    return was;
}

/**
 * @brief Update the metadata JSON object to reflect that the current layer was trusted.
 *
 * This involves deleting "Alerts" arrays and adding "Ignored" keys to the affected "Indicators".
 * This function recursively processes any contained or embedded objects to do the same for them.
 *
 * @param scan_layer_json   The JSON object representing the current scan layer's metadata.
 * @return cl_error_t       CL_SUCCESS on success, or an error code on failure.
 */
static cl_error_t metadata_json_trust_this_layer(json_object *scan_layer_json, const char *reason)
{
    cl_error_t status = CL_ERROR;
    cl_error_t ret;
    int json_ret;

    if (!scan_layer_json) {
        cli_errmsg("metadata_json_trust_this_layer: invalid JSON object\n");
        status = CL_ENULLARG;
        goto done;
    }

    // Trust the current layer's metadata by renaming the "Indicators" and "Alerts" arrays.
    json_object *indicators = NULL;
    if (json_object_object_get_ex(scan_layer_json, "Indicators", &indicators)) {
        // For each indicator in the array, add the "Ignored" string and set to the "reason".
        size_t num_indicators = json_object_array_length(indicators);
        size_t i;
        for (i = 0; i < num_indicators; i++) {
            json_object *indicator = json_object_array_get_idx(indicators, i);
            if (indicator) {
                json_object *ignored = json_object_new_string(reason);
                if (!ignored) {
                    cli_errmsg("metadata_json_trust_this_layer: no memory for json ignored indicator object\n");
                    status = CL_EMEM;
                    goto done;
                }
                json_ret = json_object_object_add(indicator, "Ignored", ignored);
                if (0 != json_ret) {
                    cli_errmsg("metadata_json_trust_this_layer: Failed to add Ignored boolean to indicator object\n");
                    status = CL_ERROR;
                    goto done;
                }
            }
        }

        // Now recursively find any contained objects and rename their "Indicators" arrays too.
        json_object *contained_objects = NULL;
        if (json_object_object_get_ex(scan_layer_json, "ContainedObjects", &contained_objects)) {
            size_t i;
            size_t num_objects = json_object_array_length(contained_objects);
            for (i = 0; i < num_objects; i++) {
                json_object *contained_object = json_object_array_get_idx(contained_objects, i);
                if (contained_object) {
                    ret = metadata_json_trust_this_layer(contained_object, reason);
                    if (ret != CL_SUCCESS) {
                        cli_errmsg("metadata_json_trust_this_layer: failed to update metadata JSON for contained object: %s\n", cl_strerror(ret));
                    }
                }
            }
        }

        // Do the same process for any "EmbeddedObjects" too.
        json_object *embedded_objects = NULL;
        if (json_object_object_get_ex(scan_layer_json, "EmbeddedObjects", &embedded_objects)) {
            size_t i;
            size_t num_objects = json_object_array_length(embedded_objects);
            for (i = 0; i < num_objects; i++) {
                json_object *embedded_object = json_object_array_get_idx(embedded_objects, i);
                if (embedded_object) {
                    ret = metadata_json_trust_this_layer(embedded_object, reason);
                    if (ret != CL_SUCCESS) {
                        cli_errmsg("metadata_json_trust_this_layer: failed to update metadata JSON for embedded object: %s\n", cl_strerror(ret));
                    }
                }
            }
        }
    }

    // Remove the "Alerts" entry.
    json_object_object_del(scan_layer_json, "Alerts");

    status = CL_SUCCESS;

done:
    return status;
}

cl_error_t cli_trust_this_layer(cli_ctx *ctx, const char *source)
{
    cl_error_t status = CL_ERROR;

    char *reason      = NULL;
    size_t reason_len = 0;

    if (!ctx) {
        cli_errmsg("cli_trust_this_layer: invalid context\n");
        status = CL_ENULLARG;
        goto done;
    }

    if (NULL != ctx->recursion_stack[ctx->recursion_level].evidence) {
        evidence_free(ctx->recursion_stack[ctx->recursion_level].evidence);
        ctx->recursion_stack[ctx->recursion_level].evidence = NULL;
        ctx->this_layer_evidence                            = NULL;
    }

    ctx->recursion_stack[ctx->recursion_level].verdict = CL_VERDICT_TRUSTED;

    if (SCAN_COLLECT_METADATA && ctx->this_layer_metadata_json) {
        reason_len = strlen("Object ") + SIZE_T_CHARLEN + strlen(" trusted by ") + strlen(source) + 1;
        reason     = malloc(reason_len);
        if (!reason) {
            cli_errmsg("cli_trust_this_layer: no memory for reason string\n");
            status = CL_EMEM;
            goto done;
        }
        snprintf(reason, reason_len, "Object %zu trusted by %s",
                 ctx->recursion_stack[ctx->recursion_level].object_id, source);

        status = metadata_json_trust_this_layer(ctx->this_layer_metadata_json, reason);
        if (status != CL_SUCCESS) {
            cli_errmsg("cli_trust_this_layer: failed to update metadata JSON to reflect trusted layer: %s\n", cl_strerror(status));
            goto done;
        }
    }

    status = CL_SUCCESS;

done:

    CLI_FREE_AND_SET_NULL(reason);

    return status;
}

cl_error_t cli_trust_layers(cli_ctx *ctx, uint32_t start_layer, uint32_t end_layer, const char *source)
{
    cl_error_t status = CL_ERROR;
    size_t i;

    char *reason      = NULL;
    size_t reason_len = 0;

    if (!ctx) {
        cli_errmsg("cli_trust_layers: invalid context\n");
        status = CL_ENULLARG;
        goto done;
    }

    for (i = start_layer; i <= end_layer; i++) {

        if (NULL != ctx->recursion_stack[i].evidence) {
            evidence_free(ctx->recursion_stack[i].evidence);
            ctx->recursion_stack[i].evidence = NULL;
            ctx->this_layer_evidence         = NULL;
        }

        ctx->recursion_stack[i].verdict = CL_VERDICT_TRUSTED;

        if (SCAN_COLLECT_METADATA && ctx->recursion_stack[i].metadata_json) {
            reason_len = strlen("Object ") + SIZE_T_CHARLEN + strlen(" trusted by ") + strlen(source) + 1;
            reason     = malloc(reason_len);
            if (!reason) {
                cli_errmsg("dispatch_scan_callback: no memory for reason string\n");
                return CL_EMEM;
            }
            snprintf(reason, reason_len, "Object %zu trusted by %s",
                     ctx->recursion_stack[ctx->recursion_level].object_id, source);

            status = metadata_json_trust_this_layer(ctx->recursion_stack[i].metadata_json, reason);
            if (status != CL_SUCCESS) {
                cli_errmsg("cli_trust_this_layer: failed to update metadata JSON to reflect trusted layer: %s\n", cl_strerror(status));
                goto done;
            }
        }
    }

    status = CL_SUCCESS;

done:

    CLI_FREE_AND_SET_NULL(reason);

    return status;
}
