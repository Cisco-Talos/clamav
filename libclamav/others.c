/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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
#ifdef	HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#ifndef	_WIN32
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
#ifdef	HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#ifdef	HAVE_MALLOC_H
#include <malloc.h>
#endif

#ifdef CL_THREAD_SAFE
#include <pthread.h>
#endif

#if defined(HAVE_READDIR_R_3) || defined(HAVE_READDIR_R_2)
#include <limits.h>
#include <stddef.h>
#endif

#ifdef HAVE_LIBXML2
#include <libxml/parser.h>
#endif

#include "clamav.h"
#include "others.h"
#include "regex/regex.h"
#include "ltdl.h"
#include "matcher-ac.h"
#include "matcher-pcre.h"
#include "default.h"
#include "scanners.h"
#include "bytecode.h"
#include "bytecode_api_impl.h"
#include "cache.h"
#include "readdb.h"
#include "stats.h"

cl_unrar_error_t (*cli_unrar_open)(const char *filename, void **hArchive, char **comment, uint32_t *comment_size, uint8_t debug_flag);
cl_unrar_error_t (*cli_unrar_peek_file_header)(void *hArchive, unrar_metadata_t *file_metadata);
cl_unrar_error_t (*cli_unrar_extract_file)(void* hArchive, const char* destPath, char *outputBuffer);
cl_unrar_error_t (*cli_unrar_skip_file)(void *hArchive);
void (*cli_unrar_close)(void *hArchive);

int have_rar = 0;
static int is_rar_inited = 0;

static int warn_dlerror(const char *msg)
{
    const char *err = lt_dlerror();
    if (err)
	cli_warnmsg("%s: %s\n", msg, err);
    else
	cli_warnmsg("%s\n", err);
    return 0;
}

#if 0
#define lt_preload_symbols lt_libclamav_LTX_preloaded_symbols
extern const lt_dlsymlist lt_preload_symbols[];
#endif

static int lt_init(void) {
#if 0
    /* doesn't work yet */
    if (lt_dlpreload_default(lt_preload_symbols)) {
        warn_dlerror("Cannot init ltdl preloaded symbols");
	/* not fatal */
    }
#endif
    if(lt_dlinit()) {
        warn_dlerror("Cannot init ltdl - unrar support unavailable");
        return -1;
    }
    return 0;
}

#define PASTE2(a,b) a#b
#define PASTE(a,b) PASTE2(a,b)

static lt_dlhandle lt_dlfind(const char *name, const char *featurename)
{
    static const char *suffixes[] = {
	LT_MODULE_EXT"."LIBCLAMAV_FULLVER,
	PASTE(LT_MODULE_EXT".", LIBCLAMAV_MAJORVER),
	LT_MODULE_EXT,
	"."LT_LIBEXT
    };

    const char *searchpath;
    const lt_dlinfo *info;
    char modulename[128];
    lt_dlhandle rhandle;
    unsigned i;

    if (lt_dladdsearchdir(SEARCH_LIBDIR)) {
	cli_dbgmsg("lt_dladdsearchdir failed for %s\n", SEARCH_LIBDIR);
    }

    searchpath = lt_dlgetsearchpath();
    if (!searchpath)
	searchpath = "";

    cli_dbgmsg("searching for %s, user-searchpath: %s\n", featurename, searchpath);
    for (i = 0; i < sizeof(suffixes)/sizeof(suffixes[0]); i++) {
	snprintf(modulename, sizeof(modulename), "%s%s", name, suffixes[i]);
	rhandle = lt_dlopen(modulename);
	if (rhandle)
	    break;
	cli_dbgmsg("searching for %s: %s not found\n", featurename, modulename);
    }

    if (!rhandle) {
	const char *err = lt_dlerror();
	if (!err) err = "";
#ifdef WARN_DLOPEN_FAIL
        cli_warnmsg("Cannot dlopen %s: %s - %s support unavailable\n", name, err, featurename);
#else
        cli_dbgmsg("Cannot dlopen %s: %s - %s support unavailable\n", name, err, featurename);
#endif
        return rhandle;
    }

    info = lt_dlgetinfo(rhandle);
    if (info)
	cli_dbgmsg("%s support loaded from %s %s\n", featurename, info->filename ? info->filename : "?", info->name ? info->name : "");
    return rhandle;
}

static void cli_rarload(void) {
    lt_dlhandle rhandle;

    if(is_rar_inited) return;
    is_rar_inited = 1;

    if(have_rar) return;

    rhandle = lt_dlfind("libclamunrar_iface", "unrar");
    if (!rhandle)
	return;

    if (!(cli_unrar_open = (cl_unrar_error_t(*)(const char *, void **, char **, uint32_t *, uint8_t))lt_dlsym(rhandle, "libclamunrar_iface_LTX_unrar_open")) ||
		!(cli_unrar_peek_file_header = (cl_unrar_error_t(*)(void *, unrar_metadata_t *))lt_dlsym(rhandle, "libclamunrar_iface_LTX_unrar_peek_file_header")) ||
		!(cli_unrar_extract_file = (cl_unrar_error_t(*)(void*, const char*, char*))lt_dlsym(rhandle, "libclamunrar_iface_LTX_unrar_extract_file")) ||
		!(cli_unrar_skip_file = (cl_unrar_error_t(*)(void *))lt_dlsym(rhandle, "libclamunrar_iface_LTX_unrar_skip_file")) ||
		!(cli_unrar_close = (void(*)(void *))lt_dlsym(rhandle, "libclamunrar_iface_LTX_unrar_close"))
	) {
	/* ideally we should never land here, we'd better warn so */
        cli_warnmsg("Cannot resolve: %s (version mismatch?) - unrar support unavailable\n", lt_dlerror());
        return;
    }
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

const char *cl_strerror(int clerror)
{
    switch(clerror) {
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
	    return "CL_ETIMEOUT: Time limit reached";
	/* internal (needed for debug messages) */
	case CL_EMAXREC:
	    return "CL_EMAXREC";
	case CL_EMAXSIZE:
	    return "CL_EMAXSIZE";
	case CL_EMAXFILES:
	    return "CL_EMAXFILES";
	case CL_EFORMAT:
	    return "CL_EFORMAT: Bad format or broken data";
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
	default:
	    return "Unknown error code";
    }
}

int cl_init(unsigned int initoptions)
{
        int rc;
	struct timeval tv;
	unsigned int pid = (unsigned int) getpid();

    UNUSEDPARAM(initoptions);

    cl_initialize_crypto();

    /* put dlopen() stuff here, etc. */
    if (lt_init() == 0) {
	cli_rarload();
    }
    gettimeofday(&tv, (struct timezone *) 0);
    srand(pid + tv.tv_usec*(pid+1) + clock());
    rc = bytecode_init();
    if (rc)
	return rc;
#ifdef HAVE_LIBXML2
    xmlInitParser();
#endif
    return CL_SUCCESS;
}

struct cl_engine *cl_engine_new(void)
{
    struct cl_engine *new;
    cli_intel_t *intel;

    new = (struct cl_engine *) cli_calloc(1, sizeof(struct cl_engine));
    if(!new) {
	cli_errmsg("cl_engine_new: Can't allocate memory for cl_engine\n");
	return NULL;
    }

    /* Setup default limits */
    new->maxscantime = CLI_DEFAULT_MAXSCANTIME;
    new->maxscansize = CLI_DEFAULT_MAXSCANSIZE;
    new->maxfilesize = CLI_DEFAULT_MAXFILESIZE;
    new->maxreclevel = CLI_DEFAULT_MAXRECLEVEL;
    new->maxfiles = CLI_DEFAULT_MAXFILES;
    new->min_cc_count = CLI_DEFAULT_MIN_CC_COUNT;
    new->min_ssn_count = CLI_DEFAULT_MIN_SSN_COUNT;
    /* Engine Max sizes */
    new->maxembeddedpe = CLI_DEFAULT_MAXEMBEDDEDPE;
    new->maxhtmlnormalize = CLI_DEFAULT_MAXHTMLNORMALIZE;
    new->maxhtmlnotags = CLI_DEFAULT_MAXHTMLNOTAGS;
    new->maxscriptnormalize = CLI_DEFAULT_MAXSCRIPTNORMALIZE;
    new->maxziptypercg = CLI_DEFAULT_MAXZIPTYPERCG;

    new->bytecode_security = CL_BYTECODE_TRUST_SIGNED;
    /* 5 seconds timeout */
    new->bytecode_timeout = 60000;
    new->bytecode_mode = CL_BYTECODE_MODE_AUTO;
    new->refcount = 1;
    new->ac_only = 0;
    new->ac_mindepth = CLI_DEFAULT_AC_MINDEPTH;
    new->ac_maxdepth = CLI_DEFAULT_AC_MAXDEPTH;

#ifdef USE_MPOOL
    if(!(new->mempool = mpool_create())) {
	cli_errmsg("cl_engine_new: Can't allocate memory for memory pool\n");
	free(new);
	return NULL;
    }
#endif

    new->root = mpool_calloc(new->mempool, CLI_MTARGETS, sizeof(struct cli_matcher *));
    if(!new->root) {
	cli_errmsg("cl_engine_new: Can't allocate memory for roots\n");
#ifdef USE_MPOOL
	mpool_destroy(new->mempool);
#endif
	free(new);
	return NULL;
    }

    new->dconf = cli_mpool_dconf_init(new->mempool);
    if(!new->dconf) {
	cli_errmsg("cl_engine_new: Can't initialize dynamic configuration\n");
	mpool_free(new->mempool, new->root);
#ifdef USE_MPOOL
	mpool_destroy(new->mempool);
#endif
	free(new);
	return NULL;
    }

    new->pwdbs = mpool_calloc(new->mempool, CLI_PWDB_COUNT, sizeof(struct cli_pwdb *));
    if (!new->pwdbs) {
	cli_errmsg("cl_engine_new: Can't initialize password databases\n");
	mpool_free(new->mempool, new->dconf);
	mpool_free(new->mempool, new->root);
#ifdef USE_MPOOL
	mpool_destroy(new->mempool);
#endif
	free(new);
	return NULL;
    }

    crtmgr_init(&(new->cmgr));
    if(crtmgr_add_roots(new, &(new->cmgr)))  {
	cli_errmsg("cl_engine_new: Can't initialize root certificates\n");
	mpool_free(new->mempool, new->pwdbs);
	mpool_free(new->mempool, new->dconf);
	mpool_free(new->mempool, new->root);
#ifdef USE_MPOOL
	mpool_destroy(new->mempool);
#endif
	free(new);
	return NULL;
    }

    /* Set up default stats/intel gathering callbacks */
    intel = cli_calloc(1, sizeof(cli_intel_t));
    if ((intel)) {
#ifdef CL_THREAD_SAFE
        if (pthread_mutex_init(&(intel->mutex), NULL)) {
            cli_errmsg("cli_engine_new: Cannot initialize stats gathering mutex\n");
	    mpool_free(new->mempool, new->pwdbs);
            mpool_free(new->mempool, new->dconf);
            mpool_free(new->mempool, new->root);
#ifdef USE_MPOOL
            mpool_destroy(new->mempool);
#endif
            free(new);
            free(intel);
            return NULL;
        }
#endif
        intel->engine = new;
        intel->maxsamples = STATS_MAX_SAMPLES;
        intel->maxmem = STATS_MAX_MEM;
        intel->timeout = 10;
        new->stats_data = intel;
    } else {
        new->stats_data = NULL;
    }

    new->cb_stats_add_sample = NULL;
    new->cb_stats_submit = NULL;
    new->cb_stats_flush = clamav_stats_flush;
    new->cb_stats_remove_sample = clamav_stats_remove_sample;
    new->cb_stats_decrement_count = clamav_stats_decrement_count;
    new->cb_stats_get_num = clamav_stats_get_num;
    new->cb_stats_get_size = clamav_stats_get_size;
    new->cb_stats_get_hostid = clamav_stats_get_hostid;

    /* Setup raw disk image max settings */
    new->maxpartitions = CLI_DEFAULT_MAXPARTITIONS;

    /* Engine max settings */
    new->maxiconspe = CLI_DEFAULT_MAXICONSPE;
    new->maxrechwp3 = CLI_DEFAULT_MAXRECHWP3;

    /* PCRE matching limitations */
#if HAVE_PCRE
    cli_pcre_init();
#endif
    new->pcre_match_limit = CLI_DEFAULT_PCRE_MATCH_LIMIT;
    new->pcre_recmatch_limit = CLI_DEFAULT_PCRE_RECMATCH_LIMIT;
    new->pcre_max_filesize = CLI_DEFAULT_PCRE_MAX_FILESIZE;

#ifdef HAVE_YARA

    /* YARA */
    if (cli_yara_init(new) != CL_SUCCESS) {
        cli_errmsg("cli_engine_new: failed to initialize YARA\n");
	mpool_free(new->mempool, new->pwdbs);
        mpool_free(new->mempool, new->dconf);
        mpool_free(new->mempool, new->root);
#ifdef USE_MPOOL
        mpool_destroy(new->mempool);
#endif
        free(new);
        free(intel);
        return NULL;
    }

#endif

    cli_dbgmsg("Initialized %s engine\n", cl_retver());
    return new;
}

int cl_engine_set_num(struct cl_engine *engine, enum cl_engine_field field, long long num)
{
    if(!engine)
	return CL_ENULLARG;

    /* TODO: consider adding checks and warn/errs when num overflows the
     * destination type
     */
    switch(field) {
	case CL_ENGINE_MAX_SCANSIZE:
	    engine->maxscansize = num;
	    break;
	case CL_ENGINE_MAX_FILESIZE:
	    engine->maxfilesize = num;
	    break;
	case CL_ENGINE_MAX_RECURSION:
	    if(!num) {
		cli_warnmsg("MaxRecursion: the value of 0 is not allowed, using default: %u\n", CLI_DEFAULT_MAXRECLEVEL);
		engine->maxreclevel = CLI_DEFAULT_MAXRECLEVEL;
	    } else
		engine->maxreclevel = num;
	    break;
	case CL_ENGINE_MAX_FILES:
	    engine->maxfiles = num;
	    break;
	case CL_ENGINE_MAX_EMBEDDEDPE:
	    if(num < 0) {
		cli_warnmsg("MaxEmbeddedPE: negative values are not allowed, using default: %u\n", CLI_DEFAULT_MAXEMBEDDEDPE);
		engine->maxembeddedpe = CLI_DEFAULT_MAXEMBEDDEDPE;
	    } else
		engine->maxembeddedpe = num;
	    break;
	case CL_ENGINE_MAX_HTMLNORMALIZE:
	    if(num < 0) {
		cli_warnmsg("MaxHTMLNormalize: negative values are not allowed, using default: %u\n", CLI_DEFAULT_MAXHTMLNORMALIZE);
		engine->maxhtmlnormalize = CLI_DEFAULT_MAXHTMLNORMALIZE;
	    } else
		engine->maxhtmlnormalize = num;
	    break;
	case CL_ENGINE_MAX_HTMLNOTAGS:
	    if(num < 0) {
		cli_warnmsg("MaxHTMLNoTags: negative values are not allowed, using default: %u\n", CLI_DEFAULT_MAXHTMLNOTAGS);
		engine->maxhtmlnotags = CLI_DEFAULT_MAXHTMLNOTAGS;
	    } else
		engine->maxhtmlnotags = num;
	    break;
	case CL_ENGINE_MAX_SCRIPTNORMALIZE:
	    if(num < 0) {
		cli_warnmsg("MaxScriptNormalize: negative values are not allowed, using default: %u\n", CLI_DEFAULT_MAXSCRIPTNORMALIZE);
		engine->maxscriptnormalize = CLI_DEFAULT_MAXSCRIPTNORMALIZE;
	    } else
		engine->maxscriptnormalize = num;
	    break;
	case CL_ENGINE_MAX_ZIPTYPERCG:
	    if(num < 0) {
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
	case CL_ENGINE_FORCETODISK:
	    if(num)
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
		if (!(engine->cache))
		    cli_cache_init(engine);
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
	default:
	    cli_errmsg("cl_engine_set_num: Incorrect field number\n");
	    return CL_EARG;
    }

    return CL_SUCCESS;
}

long long cl_engine_get_num(const struct cl_engine *engine, enum cl_engine_field field, int *err)
{
    if(!engine) {
	cli_errmsg("cl_engine_get_num: engine == NULL\n");
	if(err)
	    *err = CL_ENULLARG;
	return -1;
    }

    if(err)
	*err = CL_SUCCESS;

    switch(field) {
	case CL_ENGINE_DB_OPTIONS:
	    return engine->dboptions;
	case CL_ENGINE_MAX_SCANSIZE:
	    return engine->maxscansize;
	case CL_ENGINE_MAX_FILESIZE:
	    return engine->maxfilesize;
	case CL_ENGINE_MAX_RECURSION:
	    return engine->maxreclevel;
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
	    if(err)
		*err = CL_EARG;
	    return -1;
    }
}

int cl_engine_set_str(struct cl_engine *engine, enum cl_engine_field field, const char *str)
{
    if(!engine)
	return CL_ENULLARG;

    switch(field) {
	case CL_ENGINE_PUA_CATEGORIES:
	    engine->pua_cats = cli_mpool_strdup(engine->mempool, str);
	    if(!engine->pua_cats)
		return CL_EMEM;
	    break;
	case CL_ENGINE_TMPDIR:
	    engine->tmpdir = cli_mpool_strdup(engine->mempool, str);
	    if(!engine->tmpdir)
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
    if(!engine) {
	cli_errmsg("cl_engine_get_str: engine == NULL\n");
	if(err)
	    *err = CL_ENULLARG;
	return NULL;
    }

    if(err)
	*err = CL_SUCCESS;

    switch(field) {
	case CL_ENGINE_PUA_CATEGORIES:
	    return engine->pua_cats;
	case CL_ENGINE_TMPDIR:
	    return engine->tmpdir;
	default:
	    cli_errmsg("cl_engine_get: Incorrect field number\n");
	    if(err)
		*err = CL_EARG;
	    return NULL;
    }
}

struct cl_settings *cl_engine_settings_copy(const struct cl_engine *engine)
{
	struct cl_settings *settings;

    settings = (struct cl_settings *) malloc(sizeof(struct cl_settings));
    if(!settings) {
        cli_errmsg("cl_engine_settings_copy: Unable to allocate memory for settings %llu\n",
                   (long long unsigned)sizeof(struct cl_settings));
        return NULL;
    }

    settings->ac_only = engine->ac_only;
    settings->ac_mindepth = engine->ac_mindepth;
    settings->ac_maxdepth = engine->ac_maxdepth;
    settings->tmpdir = engine->tmpdir ? strdup(engine->tmpdir) : NULL;
    settings->keeptmp = engine->keeptmp;
    settings->maxscantime = engine->maxscantime;
    settings->maxscansize = engine->maxscansize;
    settings->maxfilesize = engine->maxfilesize;
    settings->maxreclevel = engine->maxreclevel;
    settings->maxfiles = engine->maxfiles;
    settings->maxembeddedpe = engine->maxembeddedpe;
    settings->maxhtmlnormalize = engine->maxhtmlnormalize;
    settings->maxhtmlnotags = engine->maxhtmlnotags;
    settings->maxscriptnormalize = engine->maxscriptnormalize;
    settings->maxziptypercg = engine->maxziptypercg;
    settings->min_cc_count = engine->min_cc_count;
    settings->min_ssn_count = engine->min_ssn_count;
    settings->bytecode_security = engine->bytecode_security;
    settings->bytecode_timeout = engine->bytecode_timeout;
    settings->bytecode_mode = engine->bytecode_mode;
    settings->pua_cats = engine->pua_cats ? strdup(engine->pua_cats) : NULL;

    settings->cb_pre_cache = engine->cb_pre_cache;
    settings->cb_pre_scan = engine->cb_pre_scan;
    settings->cb_post_scan = engine->cb_post_scan;
    settings->cb_virus_found = engine->cb_virus_found;
    settings->cb_sigload = engine->cb_sigload;
    settings->cb_sigload_ctx = engine->cb_sigload_ctx;
    settings->cb_hash = engine->cb_hash;
    settings->cb_meta = engine->cb_meta;
    settings->cb_file_props = engine->cb_file_props;
    settings->engine_options = engine->engine_options;

    settings->cb_stats_add_sample = engine->cb_stats_add_sample;
    settings->cb_stats_remove_sample = engine->cb_stats_remove_sample;
    settings->cb_stats_decrement_count = engine->cb_stats_decrement_count;
    settings->cb_stats_submit = engine->cb_stats_submit;
    settings->cb_stats_flush = engine->cb_stats_flush;
    settings->cb_stats_get_num = engine->cb_stats_get_num;
    settings->cb_stats_get_size = engine->cb_stats_get_size;
    settings->cb_stats_get_hostid = engine->cb_stats_get_hostid;

    settings->maxpartitions = engine->maxpartitions;

    settings->maxiconspe = engine->maxiconspe;
    settings->maxrechwp3 = engine->maxrechwp3;

    settings->pcre_match_limit = engine->pcre_match_limit;
    settings->pcre_recmatch_limit = engine->pcre_recmatch_limit;
    settings->pcre_max_filesize = engine->pcre_max_filesize;

    return settings;
}

int cl_engine_settings_apply(struct cl_engine *engine, const struct cl_settings *settings)
{
    engine->ac_only = settings->ac_only;
    engine->ac_mindepth = settings->ac_mindepth;
    engine->ac_maxdepth = settings->ac_maxdepth;
    engine->keeptmp = settings->keeptmp;
    engine->maxscantime = settings->maxscantime;
    engine->maxscansize = settings->maxscansize;
    engine->maxfilesize = settings->maxfilesize;
    engine->maxreclevel = settings->maxreclevel;
    engine->maxfiles = settings->maxfiles;
    engine->maxembeddedpe = settings->maxembeddedpe;
    engine->maxhtmlnormalize = settings->maxhtmlnormalize;
    engine->maxhtmlnotags = settings->maxhtmlnotags;
    engine->maxscriptnormalize = settings->maxscriptnormalize;
    engine->maxziptypercg = settings->maxziptypercg;
    engine->min_cc_count = settings->min_cc_count;
    engine->min_ssn_count = settings->min_ssn_count;
    engine->bytecode_security = settings->bytecode_security;
    engine->bytecode_timeout = settings->bytecode_timeout;
    engine->bytecode_mode = settings->bytecode_mode;
    engine->engine_options = settings->engine_options;

    if(engine->tmpdir)
	mpool_free(engine->mempool, engine->tmpdir);
    if(settings->tmpdir) {
	engine->tmpdir = cli_mpool_strdup(engine->mempool, settings->tmpdir);
	if(!engine->tmpdir)
	    return CL_EMEM;
    } else {
	engine->tmpdir = NULL;
    }

    if(engine->pua_cats)
	mpool_free(engine->mempool, engine->pua_cats);
    if(settings->pua_cats) {
	engine->pua_cats = cli_mpool_strdup(engine->mempool, settings->pua_cats);
	if(!engine->pua_cats)
	    return CL_EMEM;
    } else {
	engine->pua_cats = NULL;
    }

    engine->cb_pre_cache = settings->cb_pre_cache;
    engine->cb_pre_scan = settings->cb_pre_scan;
    engine->cb_post_scan = settings->cb_post_scan;
    engine->cb_virus_found = settings->cb_virus_found;
    engine->cb_sigload = settings->cb_sigload;
    engine->cb_sigload_ctx = settings->cb_sigload_ctx;
    engine->cb_hash = settings->cb_hash;
    engine->cb_meta = settings->cb_meta;
    engine->cb_file_props = settings->cb_file_props;

    engine->cb_stats_add_sample = settings->cb_stats_add_sample;
    engine->cb_stats_remove_sample = settings->cb_stats_remove_sample;
    engine->cb_stats_decrement_count = settings->cb_stats_decrement_count;
    engine->cb_stats_submit = settings->cb_stats_submit;
    engine->cb_stats_flush = settings->cb_stats_flush;
    engine->cb_stats_get_num = settings->cb_stats_get_num;
    engine->cb_stats_get_size = settings->cb_stats_get_size;
    engine->cb_stats_get_hostid = settings->cb_stats_get_hostid;

    engine->maxpartitions = settings->maxpartitions;

    engine->maxiconspe = settings->maxiconspe;
    engine->maxrechwp3 = settings->maxrechwp3;

    engine->pcre_match_limit = settings->pcre_match_limit;
    engine->pcre_recmatch_limit = settings->pcre_recmatch_limit;
    engine->pcre_max_filesize = settings->pcre_max_filesize;

    return CL_SUCCESS;
}

int cl_engine_settings_free(struct cl_settings *settings)
{
    if(!settings)
	return CL_ENULLARG;

    free(settings->tmpdir);
    free(settings->pua_cats);
    free(settings);
    return CL_SUCCESS;
}

void cli_check_blockmax(cli_ctx *ctx, int rc)
{
    if (SCAN_HEURISTIC_EXCEEDS_MAX && !ctx->limit_exceeded) {
        cli_append_virus (ctx, "Heuristics.Limits.Exceeded");
        ctx->limit_exceeded = 1;
        cli_dbgmsg ("Limit %s Exceeded: scanning may be incomplete and additional analysis needed for this file.\n",
            cl_strerror(rc));
    }
}

cl_error_t cli_checklimits(const char *who, cli_ctx *ctx, unsigned long need1, unsigned long need2, unsigned long need3)
{
    cl_error_t ret = CL_SUCCESS;
    unsigned long needed;

    /* if called without limits, go on, unpack, scan */
    if(!ctx) return CL_CLEAN;

    needed = (need1>need2)?need1:need2;
    needed = (needed>need3)?needed:need3;

    /* Enforce timelimit */
    ret = cli_checktimelimit(ctx);

    /* if we have global scan limits */
    if(needed && ctx->engine->maxscansize) {
        /* if the remaining scansize is too small... */
        if(ctx->engine->maxscansize-ctx->scansize<needed) {
	    /* ... we tell the caller to skip this file */
	    cli_dbgmsg("%s: scansize exceeded (initial: %lu, consumed: %lu, needed: %lu)\n", who, (unsigned long int) ctx->engine->maxscansize, (unsigned long int) ctx->scansize, needed);
	    ret = CL_EMAXSIZE;
	}
    }

    /* if we have per-file size limits, and we are overlimit... */
    if(needed && ctx->engine->maxfilesize && ctx->engine->maxfilesize<needed) {
	/* ... we tell the caller to skip this file */
        cli_dbgmsg("%s: filesize exceeded (allowed: %lu, needed: %lu)\n", who, (unsigned long int) ctx->engine->maxfilesize, needed);
	ret = CL_EMAXSIZE;
    }

    if(ctx->engine->maxfiles && ctx->scannedfiles>=ctx->engine->maxfiles) {
        cli_dbgmsg("%s: files limit reached (max: %u)\n", who, ctx->engine->maxfiles);
	ret = CL_EMAXFILES;
    }

    if (ret != CL_SUCCESS)
        cli_check_blockmax(ctx, ret);

    return ret;
}

cl_error_t cli_updatelimits(cli_ctx *ctx, unsigned long needed)
{
    cl_error_t ret = cli_checklimits("cli_updatelimits", ctx, needed, 0, 0);

    if (ret != CL_CLEAN) return ret;
    ctx->scannedfiles++;
    ctx->scansize+=needed;
    if(ctx->scansize > ctx->engine->maxscansize)
        ctx->scansize = ctx->engine->maxscansize;
    return CL_CLEAN;
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
            if (now.tv_sec > ctx->time_limit.tv_sec)
                ret = CL_ETIMEOUT;
            else if (now.tv_sec == ctx->time_limit.tv_sec && now.tv_usec > ctx->time_limit.tv_usec)
                ret = CL_ETIMEOUT;
        }
    }

done:
    return ret;
}

/*
 * Type: 1 = MD5, 2 = SHA1, 3 = SHA256
 */
char *cli_hashstream(FILE *fs, unsigned char *digcpy, int type)
{
    unsigned char digest[32];
    char buff[FILEBUFF];
    char *hashstr, *pt;
    const char *alg=NULL;
    int i, bytes, size;
    void *ctx;

    switch (type) {
        case 1:
            alg = "md5";
            size = 16;
            break;
        case 2:
            alg = "sha1";
            size = 20;
            break;
        default:
            alg = "sha256";
            size = 32;
            break;
    }

    ctx = cl_hash_init(alg);
    if (!(ctx))
        return NULL;

    while((bytes = fread(buff, 1, FILEBUFF, fs)))
        cl_update_hash(ctx, buff, bytes);

    cl_finish_hash(ctx, digest);

    if(!(hashstr = (char *) cli_calloc(size*2 + 1, sizeof(char))))
        return NULL;

    pt = hashstr;
    for(i = 0; i < size; i++) {
        sprintf(pt, "%02x", digest[i]);
        pt += 2;
    }

    if(digcpy)
        memcpy(digcpy, digest, size);

    return hashstr;
}

char *cli_hashfile(const char *filename, int type)
{
	FILE *fs;
	char *hashstr;


    if((fs = fopen(filename, "rb")) == NULL) {
	cli_errmsg("cli_hashfile(): Can't open file %s\n", filename);
	return NULL;
    }

    hashstr = cli_hashstream(fs, NULL, type);

    fclose(fs);
    return hashstr;
}

/* Function: unlink
        unlink() with error checking
*/
int cli_unlink(const char* pathname)
{
    if (unlink(pathname) == -1) {
#ifdef _WIN32
        /* Windows may fail to unlink a file if it is marked read-only,
		 * even if the user has permissions to delete the file. */
        if (-1 == _chmod(pathname, _S_IWRITE)) {
            char err[128];
            cli_warnmsg("cli_unlink: _chmod failure - %s\n", cli_strerror(errno, err, sizeof(err)));
            return 1;
        } else if (unlink(pathname) == -1) {
            char err[128];
            cli_warnmsg("cli_unlink: unlink failure - %s\n", cli_strerror(errno, err, sizeof(err)));
            return 1;
        }
        return 0;
#else
        char err[128];
        cli_warnmsg("cli_unlink: unlink failure - %s\n", cli_strerror(errno, err, sizeof(err)));
        return 1;
#endif
    }
    return 0;
}

void cli_virus_found_cb(cli_ctx * ctx)
{
    if (ctx->engine->cb_virus_found)
        ctx->engine->cb_virus_found(fmap_fd(*ctx->fmap), (const char *)*ctx->virname, ctx->cb_ctx);
}

cl_error_t cli_append_possibly_unwanted(cli_ctx *ctx, const char *virname)
{
    if (SCAN_ALLMATCHES)
        return cli_append_virus(ctx, virname);
    else if (SCAN_HEURISTIC_PRECEDENCE)
        return cli_append_virus(ctx, virname);
    else if (ctx->num_viruses == 0 && ctx->virname != NULL && *ctx->virname == NULL) {
        ctx->found_possibly_unwanted = 1;
        ctx->num_viruses++;
        *ctx->virname = virname;
    }
    return CL_CLEAN;
}

int cli_append_virus(cli_ctx * ctx, const char * virname)
{
    if (ctx->virname == NULL)
        return CL_CLEAN;
    if (ctx->fmap != NULL && (*ctx->fmap) != NULL && CL_VIRUS != cli_checkfp_virus((*ctx->fmap)->maphash, (*ctx->fmap)->len, ctx, virname))
        return CL_CLEAN;
    if (!SCAN_ALLMATCHES && ctx->num_viruses != 0)
        if (SCAN_HEURISTIC_PRECEDENCE)
            return CL_CLEAN;
    if (ctx->limit_exceeded == 0 || SCAN_ALLMATCHES) {
        ctx->num_viruses++;
        *ctx->virname = virname;
        cli_virus_found_cb(ctx);
    }
#if HAVE_JSON
    if (SCAN_COLLECT_METADATA && ctx->wrkproperty) {
        json_object *arrobj, *virobj;
        if (!json_object_object_get_ex(ctx->wrkproperty, "Viruses", &arrobj)) {
            arrobj = json_object_new_array();
            if (NULL == arrobj) {
                cli_errmsg("cli_append_virus: no memory for json virus array\n");
                return CL_EMEM;
            }
            json_object_object_add(ctx->wrkproperty, "Viruses", arrobj);
        }
        virobj = json_object_new_string(virname);
        if (NULL == virobj) {
            cli_errmsg("cli_append_virus: no memory for json virus name object\n");
            return CL_EMEM;
        }
        json_object_array_add(arrobj, virobj);
    }
#endif
    return CL_VIRUS;
}

const char * cli_get_last_virus(const cli_ctx * ctx)
{
    if (!ctx || !ctx->virname || !(*ctx->virname))
	return NULL;
    return *ctx->virname;
}

const char * cli_get_last_virus_str(const cli_ctx * ctx)
{
    const char * ret;
    if ((ret = cli_get_last_virus(ctx)))
	return ret;
    return "";
}

void cli_set_container(cli_ctx *ctx, cli_file_t type, size_t size)
{
    ctx->containers[ctx->recursion].type = type;
    ctx->containers[ctx->recursion].size = size;
    if (type >=  CL_TYPE_MSEXE && type != CL_TYPE_HTML && type != CL_TYPE_OTHER && type != CL_TYPE_IGNORED)
        ctx->containers[ctx->recursion].flag = CONTAINER_FLAG_VALID;
    else
        ctx->containers[ctx->recursion].flag = 0;
}

cli_file_t cli_get_container(cli_ctx *ctx, int index)
{
	if (index < 0)
		index = ctx->recursion + index + 1;
	while (index >= 0 && index <= (int)ctx->recursion)
	{
		if (ctx->containers[index].flag & CONTAINER_FLAG_VALID)
			return ctx->containers[index].type;
		index--;
	}
	return CL_TYPE_ANY;
}

cli_file_t cli_get_container_intermediate(cli_ctx *ctx, int index)
{
	if (index < 0)
		index = ctx->recursion + index + 1;
	if (index >= 0 && index <= (int)ctx->recursion)
		return ctx->containers[index].type;
	return CL_TYPE_ANY;
}

size_t cli_get_container_size(cli_ctx *ctx, int index)
{
	if (index < 0)
		index = ctx->recursion + index + 1;
	while (index >= 0 && index <= (int)ctx->recursion)
	{
		if (ctx->containers[index].flag & CONTAINER_FLAG_VALID)
			return ctx->containers[index].size;
		index--;
	}
	return ctx->containers[0].size;
}



#ifdef	C_WINDOWS
/*
 * Windows doesn't allow you to delete a directory while it is still open
 */
int
cli_rmdirs(const char *name)
{
	int rc;
	STATBUF statb;
	DIR *dd;
	struct dirent *dent;
#if defined(HAVE_READDIR_R_3) || defined(HAVE_READDIR_R_2)
	union {
	    struct dirent d;
	    char b[offsetof(struct dirent, d_name) + NAME_MAX + 1];
	} result;
#endif
	char err[128];


    if(CLAMSTAT(name, &statb) < 0) {
	cli_warnmsg("cli_rmdirs: Can't locate %s: %s\n", name, cli_strerror(errno, err, sizeof(err)));
	return -1;
    }

    if(!S_ISDIR(statb.st_mode)) {
	if(cli_unlink(name)) return -1;
	return 0;
    }

    if((dd = opendir(name)) == NULL)
	return -1;

    rc = 0;

#ifdef HAVE_READDIR_R_3
    while((readdir_r(dd, &result.d, &dent) == 0) && dent) {
#elif defined(HAVE_READDIR_R_2)
    while((dent = (struct dirent *)readdir_r(dd, &result.d)) != NULL) {
#else
    while((dent = readdir(dd)) != NULL) {
#endif
	    char *path;

	if(strcmp(dent->d_name, ".") == 0)
	    continue;
	if(strcmp(dent->d_name, "..") == 0)
	    continue;

	path = cli_malloc(strlen(name) + strlen(dent->d_name) + 2);

	if(path == NULL) {
        cli_errmsg("cli_rmdirs: Unable to allocate memory for path %u\n", strlen(name) + strlen(dent->d_name) + 2);
	    closedir(dd);
	    return -1;
	}

	sprintf(path, "%s\\%s", name, dent->d_name);
	rc = cli_rmdirs(path);
	free(path);
	if(rc != 0)
	    break;
    }

    closedir(dd);

    if(rmdir(name) < 0) {
	cli_errmsg("cli_rmdirs: Can't remove temporary directory %s: %s\n", name, cli_strerror(errno, err, sizeof(err)));
	return -1;
    }

    return rc;
}
#else
int cli_rmdirs(const char *dirname)
{
	DIR *dd;
	struct dirent *dent;
#if defined(HAVE_READDIR_R_3) || defined(HAVE_READDIR_R_2)
	union {
	    struct dirent d;
	    char b[offsetof(struct dirent, d_name) + NAME_MAX + 1];
	} result;
#endif
	STATBUF maind, statbuf;
	char *path;
	char err[128];


    chmod(dirname, 0700);
    if((dd = opendir(dirname)) != NULL) {
	while(CLAMSTAT(dirname, &maind) != -1) {
	    if(!rmdir(dirname)) break;
	    if(errno != ENOTEMPTY && errno != EEXIST && errno != EBADF) {
		cli_errmsg("cli_rmdirs: Can't remove temporary directory %s: %s\n", dirname, cli_strerror(errno, err, sizeof(err)));
		closedir(dd);
		return -1;
	    }

#ifdef HAVE_READDIR_R_3
	    while(!readdir_r(dd, &result.d, &dent) && dent) {
#elif defined(HAVE_READDIR_R_2)
	    while((dent = (struct dirent *) readdir_r(dd, &result.d))) {
#else
	    while((dent = readdir(dd))) {
#endif
		if(dent->d_ino)
		{
		    if(strcmp(dent->d_name, ".") && strcmp(dent->d_name, "..")) {
			path = cli_malloc(strlen(dirname) + strlen(dent->d_name) + 2);
			if(!path) {
                cli_errmsg("cli_rmdirs: Unable to allocate memory for path %llu\n", (long long unsigned)(strlen(dirname) + strlen(dent->d_name) + 2));
			    closedir(dd);
			    return -1;
			}

			sprintf(path, "%s"PATHSEP"%s", dirname, dent->d_name);

			/* stat the file */
			if(LSTAT(path, &statbuf) != -1) {
			    if(S_ISDIR(statbuf.st_mode) && !S_ISLNK(statbuf.st_mode)) {
				if(rmdir(path) == -1) { /* can't be deleted */
				    if(errno == EACCES) {
					cli_errmsg("cli_rmdirs: Can't remove some temporary directories due to access problem.\n");
					closedir(dd);
					free(path);
					return -1;
				    }
				    if(cli_rmdirs(path)) {
					cli_warnmsg("cli_rmdirs: Can't remove nested directory %s\n", path);
					free(path);
					closedir(dd);
					return -1;
				    }
				}
			    } else {
				if(cli_unlink(path)) {
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

	bs = cli_malloc(sizeof(bitset_t));
	if (!bs) {
        cli_errmsg("cli_bitset_init: Unable to allocate memory for bs %llu\n", (long long unsigned)sizeof(bitset_t));
		return NULL;
	}
	bs->length = BITSET_DEFAULT_SIZE;
	bs->bitset = cli_calloc(BITSET_DEFAULT_SIZE, 1);
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
	new_bitset = (unsigned char *) cli_realloc(bs->bitset, new_length);
	if (!new_bitset) {
		return NULL;
	}
	bs->bitset = new_bitset;
	memset(bs->bitset+bs->length, 0, new_length-bs->length);
	bs->length = new_length;
	return bs;
}

int cli_bitset_set(bitset_t *bs, unsigned long bit_offset)
{
	unsigned long char_offset;

	char_offset = bit_offset / BITS_PER_CHAR;
	bit_offset = bit_offset % BITS_PER_CHAR;

	if (char_offset >= bs->length) {
		bs = bitset_realloc(bs, char_offset+1);
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
	bit_offset = bit_offset % BITS_PER_CHAR;

	if (char_offset >= bs->length) {
		return FALSE;
	}
	return (bs->bitset[char_offset] & ((unsigned char)1 << bit_offset));
}

void cl_engine_set_clcb_pre_cache(struct cl_engine *engine, clcb_pre_cache callback) {
    engine->cb_pre_cache = callback;
}

void cl_engine_set_clcb_pre_scan(struct cl_engine *engine, clcb_pre_scan callback) {
    engine->cb_pre_scan = callback;
}

void cl_engine_set_clcb_post_scan(struct cl_engine *engine, clcb_post_scan callback) {
    engine->cb_post_scan = callback;
}

void cl_engine_set_clcb_virus_found(struct cl_engine *engine, clcb_virus_found callback) {
    engine->cb_virus_found = callback;
}

void cl_engine_set_clcb_sigload(struct cl_engine *engine, clcb_sigload callback, void *context) {
    engine->cb_sigload = callback;
    engine->cb_sigload_ctx = callback ? context : NULL;
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
