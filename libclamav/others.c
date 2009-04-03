/*
 *  Copyright (C) 2007-2008 Sourcefire, Inc.
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
#ifndef	C_WINDOWS
#include <sys/wait.h>
#include <sys/time.h>
#include <dirent.h>
#endif
#include <time.h>
#include <fcntl.h>
#ifndef	C_WINDOWS
#include <pwd.h>
#endif
#include <errno.h>
#include "target.h"
#ifndef	C_WINDOWS
#include <sys/time.h>
#endif
#ifdef	HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#ifdef	HAVE_MALLOC_H
#include <malloc.h>
#endif
#if	defined(_MSC_VER) && defined(_DEBUG)
#include <crtdbg.h>
#endif

#if defined(HAVE_READDIR_R_3) || defined(HAVE_READDIR_R_2)
#include <limits.h>
#include <stddef.h>
#endif

#include "clamav.h"
#include "others.h"
#include "md5.h"
#include "cltypes.h"
#include "regex/regex.h"
#include "ltdl.h"
#include "matcher-ac.h"
#include "default.h"

#ifndef	O_BINARY
#define	O_BINARY	0
#endif

#ifdef        C_WINDOWS
#undef        P_tmpdir
#define       P_tmpdir        "C:\\WINDOWS\\TEMP"
#endif

int (*cli_unrar_open)(int fd, const char *dirname, unrar_state_t *state);
int (*cli_unrar_extract_next_prepare)(unrar_state_t *state, const char *dirname);
int (*cli_unrar_extract_next)(unrar_state_t *state, const char *dirname);
void (*cli_unrar_close)(unrar_state_t *state);
int have_rar = 0;
static int is_rar_initd = 0;

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

#define PASTE(a,b) a#b

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
    int canretry=1;
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

    if(is_rar_initd) return;
    is_rar_initd = 1;

    rhandle = lt_dlfind("libclamunrar_iface", "unrar");
    if (!rhandle)
	return;

    if (!(cli_unrar_open = (int(*)(int, const char *, unrar_state_t *))lt_dlsym(rhandle, "libclamunrar_iface_LTX_unrar_open")) ||
	!(cli_unrar_extract_next_prepare = (int(*)(unrar_state_t *, const char *))lt_dlsym(rhandle, "libclamunrar_iface_LTX_unrar_extract_next_prepare")) ||
	!(cli_unrar_extract_next = (int(*)(unrar_state_t *, const char *))lt_dlsym(rhandle, "libclamunrar_iface_LTX_unrar_extract_next")) ||
	!(cli_unrar_close = (void(*)(unrar_state_t *))lt_dlsym(rhandle, "libclamunrar_iface_LTX_unrar_close"))
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
	/* internal (needed for debug messages) */
	case CL_EMAXREC:
	    return "CL_EMAXREC";
	case CL_EMAXSIZE:
	    return "CL_EMAXSIZE";
	case CL_EMAXFILES:
	    return "CL_EMAXFILES";
	case CL_EFORMAT:
	    return "CL_EFORMAT: Bad format or broken data";
	default:
	    return "Unknown error code";
    }
}

int cl_init(unsigned int initoptions)
{
    /* put dlopen() stuff here, etc. */
    if (lt_init() == 0) {
	cli_rarload();
    }
    return CL_SUCCESS;
}

struct cl_engine *cl_engine_new(void)
{
	struct cl_engine *new;


    new = (struct cl_engine *) cli_calloc(1, sizeof(struct cl_engine));
    if(!new) {
	cli_errmsg("cl_engine_new: Can't allocate memory for cl_engine\n");
	return NULL;
    }

    /* Setup default limits */
    new->maxscansize = CLI_DEFAULT_MAXSCANSIZE;
    new->maxfilesize = CLI_DEFAULT_MAXFILESIZE;
    new->maxreclevel = CLI_DEFAULT_MAXRECLEVEL;
    new->maxfiles = CLI_DEFAULT_MAXFILES;
    new->min_cc_count = CLI_DEFAULT_MIN_CC_COUNT;
    new->min_ssn_count = CLI_DEFAULT_MIN_SSN_COUNT;

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
	    engine->maxreclevel = num;
	    break;
	case CL_ENGINE_MAX_FILES:
	    engine->maxfiles = num;
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
    if(!settings)
	return NULL;

    settings->ac_only = engine->ac_only;
    settings->ac_mindepth = engine->ac_mindepth;
    settings->ac_maxdepth = engine->ac_maxdepth;
    settings->tmpdir = engine->tmpdir ? strdup(engine->tmpdir) : NULL;
    settings->keeptmp = engine->keeptmp;
    settings->maxscansize = engine->maxscansize;
    settings->maxfilesize = engine->maxfilesize;
    settings->maxreclevel = engine->maxreclevel;
    settings->maxfiles = engine->maxfiles;
    settings->min_cc_count = engine->min_cc_count;
    settings->min_ssn_count = engine->min_ssn_count;
    settings->pua_cats = engine->pua_cats ? strdup(engine->pua_cats) : NULL;

    return settings;
}

int cl_engine_settings_apply(struct cl_engine *engine, const struct cl_settings *settings)
{
    engine->ac_only = settings->ac_only;
    engine->ac_mindepth = settings->ac_mindepth;
    engine->ac_maxdepth = settings->ac_maxdepth;
    engine->keeptmp = settings->keeptmp;
    engine->maxscansize = settings->maxscansize;
    engine->maxfilesize = settings->maxfilesize;
    engine->maxreclevel = settings->maxreclevel;
    engine->maxfiles = settings->maxfiles;
    engine->min_cc_count = settings->min_cc_count;
    engine->min_ssn_count = settings->min_ssn_count;

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

int cli_checklimits(const char *who, cli_ctx *ctx, unsigned long need1, unsigned long need2, unsigned long need3) {
    int ret = CL_SUCCESS;
    unsigned long needed;

    /* if called without limits, go on, unpack, scan */
    if(!ctx) return CL_CLEAN;

    needed = (need1>need2)?need1:need2;
    needed = (needed>need3)?needed:need3;

    /* if we have global scan limits */
    if(needed && ctx->engine->maxscansize) {
        /* if the remaining scansize is too small... */
        if(ctx->engine->maxscansize-ctx->scansize<needed) {
	    /* ... we tell the caller to skip this file */
	    cli_dbgmsg("%s: scansize exceeded (initial: %lu, remaining: %lu, needed: %lu)\n", who, ctx->engine->maxscansize, ctx->scansize, needed);
	    ret = CL_EMAXSIZE;
	}
    }

    /* if we have per-file size limits, and we are overlimit... */
    if(needed && ctx->engine->maxfilesize && ctx->engine->maxfilesize<needed) {
	/* ... we tell the caller to skip this file */
        cli_dbgmsg("%s: filesize exceeded (allowed: %lu, needed: %lu)\n", who, ctx->engine->maxfilesize, needed);
	ret = CL_EMAXSIZE;
    }

    if(ctx->engine->maxfiles && ctx->scannedfiles>=ctx->engine->maxfiles) {
        cli_dbgmsg("%s: files limit reached (max: %u)\n", who, ctx->engine->maxfiles);
	return CL_EMAXFILES;
    }
    return ret;
}

int cli_updatelimits(cli_ctx *ctx, unsigned long needed) {
    int ret=cli_checklimits("cli_updatelimits", ctx, needed, 0, 0);

    if (ret != CL_CLEAN) return ret;
    ctx->scannedfiles++;
    ctx->scansize+=needed;
    if(ctx->scansize > ctx->engine->maxscansize)
        ctx->scansize = ctx->engine->maxscansize;
    return CL_CLEAN;
}

unsigned char *cli_md5digest(int desc)
{
	unsigned char *digest;
	char buff[FILEBUFF];
	cli_md5_ctx ctx;
	int bytes;


    if(!(digest = cli_malloc(16)))
	return NULL;

    cli_md5_init(&ctx);

    while((bytes = cli_readn(desc, buff, FILEBUFF)))
	cli_md5_update(&ctx, buff, bytes);

    cli_md5_final(digest, &ctx);

    return digest;
}

char *cli_md5stream(FILE *fs, unsigned char *digcpy)
{
	unsigned char digest[16];
	char buff[FILEBUFF];
	cli_md5_ctx ctx;
	char *md5str, *pt;
	int i, bytes;


    cli_md5_init(&ctx);

    while((bytes = fread(buff, 1, FILEBUFF, fs)))
	cli_md5_update(&ctx, buff, bytes);

    cli_md5_final(digest, &ctx);

    if(!(md5str = (char *) cli_calloc(32 + 1, sizeof(char))))
	return NULL;

    pt = md5str;
    for(i = 0; i < 16; i++) {
	sprintf(pt, "%02x", digest[i]);
	pt += 2;
    }

    if(digcpy)
	memcpy(digcpy, digest, 16);

    return md5str;
}

char *cli_md5file(const char *filename)
{
	FILE *fs;
	char *md5str;


    if((fs = fopen(filename, "rb")) == NULL) {
	cli_errmsg("cli_md5file(): Can't read file %s\n", filename);
	return NULL;
    }

    md5str = cli_md5stream(fs, NULL);
    fclose(fs);

    return md5str;
}

/* Function: unlink
        unlink() with error checking
*/
int cli_unlink(const char *pathname)
{
	if (unlink(pathname)==-1) {
	    char err[128];
	    cli_warnmsg("cli_unlink: failure - %s\n", cli_strerror(errno, err, sizeof(err)));
	    return 1;
	}
	return 0;
}

#ifdef	C_WINDOWS
/*
 * Windows doesn't allow you to delete a directory while it is still open
 */
int
cli_rmdirs(const char *name)
{
	int rc;
	struct stat statb;	
	DIR *dd;
	struct dirent *dent;
#if defined(HAVE_READDIR_R_3) || defined(HAVE_READDIR_R_2)
	union {
	    struct dirent d;
	    char b[offsetof(struct dirent, d_name) + NAME_MAX + 1];
	} result;
#endif
	char err[128];


    if(stat(name, &statb) < 0) {
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
	struct stat maind, statbuf;
	char *path;
	char err[128];


    chmod(dirname, 0700);
    if((dd = opendir(dirname)) != NULL) {
	while(stat(dirname, &maind) != -1) {
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
#if	(!defined(C_INTERIX)) && (!defined(C_WINDOWS))
		if(dent->d_ino)
#endif
		{
		    if(strcmp(dent->d_name, ".") && strcmp(dent->d_name, "..")) {
			path = cli_malloc(strlen(dirname) + strlen(dent->d_name) + 2);
			if(!path) {
			    closedir(dd);
			    return -1;
			}

			sprintf(path, "%s/%s", dirname, dent->d_name);

			/* stat the file */
			if(lstat(path, &statbuf) != -1) {
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
#define FALSE (0)
#define TRUE (1)

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
		return NULL;
	}
	bs->length = BITSET_DEFAULT_SIZE;
	bs->bitset = cli_calloc(BITSET_DEFAULT_SIZE, 1);
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

