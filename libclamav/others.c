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

#ifdef CL_THREAD_SAFE
#  include <pthread.h>
static pthread_mutex_t cli_gentemp_mutex = PTHREAD_MUTEX_INITIALIZER;

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

static unsigned char name_salt[16] = { 16, 38, 97, 12, 8, 4, 72, 196, 217, 144, 33, 124, 18, 11, 17, 253 };

int (*cli_unrar_open)(int fd, const char *dirname, unrar_state_t *state);
int (*cli_unrar_extract_next_prepare)(unrar_state_t *state, const char *dirname);
int (*cli_unrar_extract_next)(unrar_state_t *state, const char *dirname);
void (*cli_unrar_close)(unrar_state_t *state);
int have_rar = 0;
static int is_rar_initd = 0;

static void cli_rarload(void) {
    lt_dlhandle rhandle;

    if(is_rar_initd) return;
    is_rar_initd = 1;
    if(lt_dlinit()) {
        cli_warnmsg("Cannot init ltdl - unrar support unavailable\n");
        return;
    }
    rhandle = lt_dlopenext("libclamunrar_iface");
    if (!rhandle) {
#ifdef WARN_DLOPEN_FAIL
        cli_warnmsg("Cannot dlopen: %s - unrar support unavailable\n", lt_dlerror());
#else
        cli_dbgmsg("Cannot dlopen: %s - unrar support unavailable\n", lt_dlerror());
#endif
        return;
    }
    if (!(cli_unrar_open = (int(*)(int, const char *, unrar_state_t *))lt_dlsym(rhandle, "unrar_open")) ||
	!(cli_unrar_extract_next_prepare = (int(*)(unrar_state_t *, const char *))lt_dlsym(rhandle, "unrar_extract_next_prepare")) ||
	!(cli_unrar_extract_next = (int(*)(unrar_state_t *, const char *))lt_dlsym(rhandle, "unrar_extract_next")) ||
	!(cli_unrar_close = (void(*)(unrar_state_t *))lt_dlsym(rhandle, "unrar_close"))
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
	default:
	    return "Unknown error code";
    }
}

int cl_init(unsigned int options)
{
    /* put dlopen() stuff here, etc. */
    cli_rarload();
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

int cl_engine_set(struct cl_engine *engine, enum cl_engine_field field, const void *val)
{
    if(!engine || !val)
	return CL_ENULLARG;

    switch(field) {
	case CL_ENGINE_MAX_SCANSIZE:
	    engine->maxscansize = *((const uint64_t *) val);
	    break;
	case CL_ENGINE_MAX_FILESIZE:
	    engine->maxfilesize = *((const uint64_t *) val);
	    break;
	case CL_ENGINE_MAX_RECURSION:
	    engine->maxreclevel = *((const uint32_t *) val);
	    break;
	case CL_ENGINE_MAX_FILES:
	    engine->maxfiles = *((const uint32_t *) val);
	    break;
	case CL_ENGINE_MIN_CC_COUNT:
	    engine->min_cc_count = *((const uint32_t *) val);
	    break;
	case CL_ENGINE_MIN_SSN_COUNT:
	    engine->min_ssn_count = *((const uint32_t *) val);
	    break;
	case CL_ENGINE_PUA_CATEGORIES:
	    engine->pua_cats = cli_mpool_strdup(engine->mempool, (const char *) val);
	    if(!engine->pua_cats)
		return CL_EMEM;
	    break;
	case CL_ENGINE_DB_VERSION:
	case CL_ENGINE_DB_TIME:
	    cli_warnmsg("cl_engine_set: The field is read only\n");
	    break;
	case CL_ENGINE_AC_ONLY:
	    engine->ac_only = *((const uint32_t *) val);
	    break;
	case CL_ENGINE_AC_MINDEPTH:
	    engine->ac_mindepth = *((const uint32_t *) val);
	    break;
	case CL_ENGINE_AC_MAXDEPTH:
	    engine->ac_maxdepth = *((const uint32_t *) val);
	    break;
	case CL_ENGINE_TMPDIR:
	    engine->tmpdir = cli_mpool_strdup(engine->mempool, (const char *) val);
	    if(!engine->tmpdir)
		return CL_EMEM;
	    break;
	case CL_ENGINE_KEEPTMP:
	    engine->keeptmp = *((const uint32_t *) val);
	    break;
	default:
	    cli_errmsg("cl_engine_set: Incorrect field number\n");
	    return CL_ENULLARG; /* FIXME */
    }

    return CL_SUCCESS;
}

int cl_engine_get(const struct cl_engine *engine, enum cl_engine_field field, void *val)
{
    if(!engine || !val)
	return CL_ENULLARG;

    switch(field) {
	case CL_ENGINE_MAX_SCANSIZE:
	    *((uint64_t *) val) = engine->maxscansize;
	    break;
	case CL_ENGINE_MAX_FILESIZE:
	    *((uint64_t *) val) = engine->maxfilesize;
	    break;
	case CL_ENGINE_MAX_RECURSION:
	    *((uint32_t *) val) = engine->maxreclevel;
	    break;
	case CL_ENGINE_MAX_FILES:
	    *((uint32_t *) val) = engine->maxfiles;
	    break;
	case CL_ENGINE_MIN_CC_COUNT:
	    *((uint32_t *) val) = engine->min_cc_count;
	    break;
	case CL_ENGINE_MIN_SSN_COUNT:
	    *((uint32_t *) val) = engine->min_ssn_count;
	    break;
	case CL_ENGINE_PUA_CATEGORIES:
	    if(engine->pua_cats)
		strncpy((char *) val, engine->pua_cats, 128);
	    break;
	case CL_ENGINE_DB_VERSION:
	    *((uint32_t *) val) = engine->dbversion[0];
	    break;
	case CL_ENGINE_DB_TIME:
	    /* time_t may be 64-bit! */
	    *((time_t *) val) = engine->dbversion[1];
	    break;
	case CL_ENGINE_AC_ONLY:
	    *((uint32_t *) val) = engine->ac_only;
	    break;
	case CL_ENGINE_AC_MINDEPTH:
	    *((uint32_t *) val) = engine->ac_mindepth;
	    break;
	case CL_ENGINE_AC_MAXDEPTH:
	    *((uint32_t *) val) = engine->ac_maxdepth;
	    break;
	case CL_ENGINE_TMPDIR:
	    if(engine->tmpdir)
		strncpy((char *) val, engine->tmpdir, 128);
	    break;
	case CL_ENGINE_KEEPTMP:
	    *((uint32_t *) val) = engine->keeptmp;
	    break;
	default:
	    cli_errmsg("cl_engine_get: Incorrect field number\n");
	    return CL_ENULLARG; /* FIXME */
    }

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

static char *cli_md5buff(const unsigned char *buffer, unsigned int len, unsigned char *dig)
{
	unsigned char digest[16];
	char *md5str, *pt;
	cli_md5_ctx ctx;
	int i;


    cli_md5_init(&ctx);
    cli_md5_update(&ctx, buffer, len);
    cli_md5_final(digest, &ctx);

    if(dig)
	memcpy(dig, digest, 16);

    if(!(md5str = (char *) cli_calloc(32 + 1, sizeof(char))))
	return NULL;

    pt = md5str;
    for(i = 0; i < 16; i++) {
	sprintf(pt, "%02x", digest[i]);
	pt += 2;
    }

    return md5str;
}

unsigned int cli_rndnum(unsigned int max)
{
    if(name_salt[0] == 16) { /* minimizes re-seeding after the first call to cli_gentemp() */
	    struct timeval tv;
	gettimeofday(&tv, (struct timezone *) 0);
	srand(tv.tv_usec+clock());
    }

    return 1 + (unsigned int) (max * (rand() / (1.0 + RAND_MAX)));
}

char *cli_gentemp(const char *dir)
{
	char *name, *tmp;
        const char *mdir;
	unsigned char salt[16 + 32];
	int i;

    if(!dir) {
	if((mdir = getenv("TMPDIR")) == NULL)
#ifdef P_tmpdir
	    mdir = P_tmpdir;
#else
	    mdir = "/tmp";
#endif
    } else
	mdir = dir;

    name = (char *) cli_calloc(strlen(mdir) + 1 + 32 + 1 + 7, sizeof(char));
    if(!name) {
	cli_dbgmsg("cli_gentemp('%s'): out of memory\n", mdir);
	return NULL;
    }

#ifdef CL_THREAD_SAFE
    pthread_mutex_lock(&cli_gentemp_mutex);
#endif

    memcpy(salt, name_salt, 16);

    for(i = 16; i < 48; i++)
	salt[i] = cli_rndnum(255);

    tmp = cli_md5buff(salt, 48, name_salt);

#ifdef CL_THREAD_SAFE
    pthread_mutex_unlock(&cli_gentemp_mutex);
#endif

    if(!tmp) {
	free(name);
	cli_dbgmsg("cli_gentemp('%s'): out of memory\n", mdir);
	return NULL;
    }

#ifdef	C_WINDOWS
	sprintf(name, "%s\\clamav-", mdir);
#else
	sprintf(name, "%s/clamav-", mdir);
#endif
    strncat(name, tmp, 32);
    free(tmp);

    return(name);
}

int cli_gentempfd(const char *dir, char **name, int *fd)
{

    *name = cli_gentemp(dir);
    if(!*name)
	return CL_EMEM;

    *fd = open(*name, O_RDWR|O_CREAT|O_TRUNC|O_BINARY|O_EXCL, S_IRWXU);
    /*
     * EEXIST is almost impossible to occur, so we just treat it as other
     * errors
     */
   if(*fd == -1) {
	cli_errmsg("cli_gentempfd: Can't create temporary file %s: %s\n", *name, strerror(errno));
	free(*name);
	return CL_ECREAT;
    }

    return CL_SUCCESS;
}

/* Function: unlink
        unlink() with error checking
*/
int cli_unlink(const char *pathname)
{
	if (unlink(pathname)==-1) {
	    cli_warnmsg("cli_unlink: failure - %s\n", strerror(errno));
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


    if(stat(name, &statb) < 0) {
	cli_warnmsg("cli_rmdirs: Can't locate %s: %s\n", name, strerror(errno));
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
	cli_errmsg("cli_rmdirs: Can't remove temporary directory %s: %s\n", name, strerror(errno));
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


    chmod(dirname, 0700);
    if((dd = opendir(dirname)) != NULL) {
	while(stat(dirname, &maind) != -1) {
	    if(!rmdir(dirname)) break;
	    if(errno != ENOTEMPTY && errno != EEXIST && errno != EBADF) {
		cli_errmsg("cli_rmdirs: Can't remove temporary directory %s: %s\n", dirname, strerror(errno));
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

