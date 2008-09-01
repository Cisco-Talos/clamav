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
#ifndef CLI_MEMFUNSONLY
static pthread_mutex_t cli_gentemp_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

# ifndef HAVE_CTIME_R
static pthread_mutex_t cli_ctime_mutex = PTHREAD_MUTEX_INITIALIZER;
# endif

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

#ifndef	O_BINARY
#define	O_BINARY	0
#endif

#ifdef        C_WINDOWS
#undef        P_tmpdir
#define       P_tmpdir        "C:\\WINDOWS\\TEMP"
#endif

#define CL_FLEVEL 35 /* don't touch it */

uint8_t cli_debug_flag = 0, cli_leavetemps_flag = 0;

#ifndef CLI_MEMFUNSONLY
static unsigned char name_salt[16] = { 16, 38, 97, 12, 8, 4, 72, 196, 217, 144, 33, 124, 18, 11, 17, 253 };
#endif

#define MSGCODE(x)					    \
	va_list args;					    \
	int len = sizeof(x) - 1;			    \
	char buff[BUFSIZ];				    \
    strncpy(buff, x, len);				    \
    buff[BUFSIZ-1]='\0';				    \
    va_start(args, str);				    \
    vsnprintf(buff + len, sizeof(buff) - len, str, args);   \
    buff[sizeof(buff) - 1] = '\0';			    \
    fputs(buff, stderr);				    \
    va_end(args)


void cli_warnmsg(const char *str, ...)
{
    MSGCODE("LibClamAV Warning: ");
}

void cli_errmsg(const char *str, ...)
{
    MSGCODE("LibClamAV Error: ");
}

void cli_dbgmsg_internal(const char *str, ...)
{
    MSGCODE("LibClamAV debug: ");
}

#ifndef CLI_MEMFUNSONLY
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
	case CL_CLEAN:
	    return "No viruses detected";
	case CL_VIRUS:
	    return "Virus(es) detected";
	case CL_EMAXREC:
	    return "Recursion limit exceeded";
	case CL_EMAXSIZE:
	    return "File size limit exceeded";
	case CL_EMAXFILES:
	    return "Files number limit exceeded";
	case CL_ERAR:
	    return "RAR module failure";
	case CL_EZIP:
	    return "Zip module failure";
	case CL_EGZIP:
	    return "GZip module failure";
	case CL_EMSCOMP:
	    return "MS Expand module failure";
	case CL_EMSCAB:
	    return "MS CAB module failure";
	case CL_EOLE2:
	    return "OLE2 module failure";
	case CL_ETMPFILE:
	    return "Unable to create temporary file";
	case CL_ETMPDIR:
	    return "Unable to create temporary directory";
	case CL_EMEM:
	    return "Unable to allocate memory";
	case CL_EOPEN:
	    return "Unable to open file or directory";
	case CL_EMALFDB:
	    return "Malformed database";
	case CL_EPATSHORT:
	    return "Too short pattern detected";
	case CL_ECVD:
	    return "Broken or not a CVD file";
	case CL_ECVDEXTR:
	    return "CVD extraction failure";
	case CL_EMD5:
	    return "MD5 verification error";
	case CL_EDSIG:
	    return "Digital signature verification error";
	case CL_ENULLARG:
	    return "Null argument passed while initialized is required";
	case CL_EIO:
	    return "Input/Output error";
	case CL_EFORMAT:
	    return "Bad format or broken data";
	case CL_ESUPPORT:
	    return "Not supported data format";
	case CL_EARJ:
	    return "ARJ module failure";
	default:
	    return "Unknown error code";
    }
}

int cli_checklimits(const char *who, cli_ctx *ctx, unsigned long need1, unsigned long need2, unsigned long need3) {
    int ret = CL_SUCCESS;
    unsigned long needed;

    /* if called without limits, go on, unpack, scan */
    if(!ctx || !ctx->limits) return CL_CLEAN;

    needed = (need1>need2)?need1:need2;
    needed = (needed>need3)?needed:need3;

    /* if we have global scan limits */
    if(needed && ctx->limits->maxscansize) {
        /* if the remaining scansize is too small... */
        if(ctx->limits->maxscansize-ctx->scansize<needed) {
	    /* ... we tell the caller to skip this file */
	    cli_dbgmsg("%s: scansize exceeded (initial: %lu, remaining: %lu, needed: %lu)\n", who, ctx->limits->maxscansize, ctx->scansize, needed);
	    ret = CL_EMAXSIZE;
	}
    }

    /* if we have per-file size limits, and we are overlimit... */
    if(needed && ctx->limits->maxfilesize && ctx->limits->maxfilesize<needed) {
	/* ... we tell the caller to skip this file */
        cli_dbgmsg("%s: filesize exceeded (allowed: %lu, needed: %lu)\n", who, ctx->limits->maxfilesize, needed);
	ret = CL_EMAXSIZE;
    }

    if(ctx->limits->maxfiles && ctx->scannedfiles>=ctx->limits->maxfiles) {
        cli_dbgmsg("%s: files limit reached (max: %u)\n", who, ctx->limits->maxfiles);
	return CL_EMAXFILES;
    }
    return ret;
}

int cli_updatelimits(cli_ctx *ctx, unsigned long needed) {
    int ret=cli_checklimits("cli_updatelimits", ctx, needed, 0, 0);

    if (ret != CL_CLEAN) return ret;
    ctx->scannedfiles++;
    ctx->scansize+=needed;
    if(ctx->scansize > ctx->limits->maxscansize)
        ctx->scansize = ctx->limits->maxscansize;
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
#endif

void *cli_malloc(size_t size)
{
	void *alloc;


    if(!size || size > CLI_MAX_ALLOCATION) {
	cli_errmsg("cli_malloc(): Attempt to allocate %lu bytes. Please report to http://bugs.clamav.net\n", (unsigned long int) size);
	return NULL;
    }

#if defined(_MSC_VER) && defined(_DEBUG)
    alloc = _malloc_dbg(size, _NORMAL_BLOCK, __FILE__, __LINE__);
#else
    alloc = malloc(size);
#endif

    if(!alloc) {
	cli_errmsg("cli_malloc(): Can't allocate memory (%lu bytes).\n", (unsigned long int) size);
	perror("malloc_problem");
	return NULL;
    } else return alloc;
}

void *cli_calloc(size_t nmemb, size_t size)
{
	void *alloc;


    if(!size || size > CLI_MAX_ALLOCATION) {
	cli_errmsg("cli_calloc(): Attempt to allocate %lu bytes. Please report to http://bugs.clamav.net\n", (unsigned long int) size);
	return NULL;
    }

#if defined(_MSC_VER) && defined(_DEBUG)
    alloc = _calloc_dbg(nmemb, size, _NORMAL_BLOCK, __FILE__, __LINE__);
#else
    alloc = calloc(nmemb, size);
#endif

    if(!alloc) {
	cli_errmsg("cli_calloc(): Can't allocate memory (%lu bytes).\n", (unsigned long int) (nmemb * size));
	perror("calloc_problem");
	return NULL;
    } else return alloc;
}

void *cli_realloc(void *ptr, size_t size)
{
	void *alloc;


    if(!size || size > CLI_MAX_ALLOCATION) {
	cli_errmsg("cli_realloc(): Attempt to allocate %lu bytes. Please report to http://bugs.clamav.net\n", (unsigned long int) size);
	return NULL;
    }

    alloc = realloc(ptr, size);

    if(!alloc) {
	cli_errmsg("cli_realloc(): Can't re-allocate memory to %lu bytes.\n", (unsigned long int) size);
	perror("realloc_problem");
	return NULL;
    } else return alloc;
}

void *cli_realloc2(void *ptr, size_t size)
{
	void *alloc;


    if(!size || size > CLI_MAX_ALLOCATION) {
	cli_errmsg("cli_realloc2(): Attempt to allocate %lu bytes. Please report to http://bugs.clamav.net\n", (unsigned long int) size);
	return NULL;
    }

    alloc = realloc(ptr, size);

    if(!alloc) {
	cli_errmsg("cli_realloc2(): Can't re-allocate memory to %lu bytes.\n", (unsigned long int) size);
	perror("realloc_problem");
	if(ptr)
	    free(ptr);
	return NULL;
    } else return alloc;
}

char *cli_strdup(const char *s)
{
        char *alloc;


    if(s == NULL) {
        cli_errmsg("cli_strdup(): s == NULL. Please report to http://bugs.clamav.net\n");
        return NULL;
    }

#if defined(_MSC_VER) && defined(_DEBUG)
    alloc = _strdup_dbg(s, _NORMAL_BLOCK, __FILE__, __LINE__);
#else
    alloc = strdup(s);
#endif

    if(!alloc) {
        cli_errmsg("cli_strdup(): Can't allocate memory (%u bytes).\n", (unsigned int) strlen(s));
        perror("strdup_problem");
        return NULL;
    }

    return alloc;
}

#ifndef CLI_MEMFUNSONLY
unsigned int cli_rndnum(unsigned int max)
{
    if(name_salt[0] == 16) { /* minimizes re-seeding after the first call to cli_gentemp() */
	    struct timeval tv;
	gettimeofday(&tv, (struct timezone *) 0);
	srand(tv.tv_usec+clock());
    }

    return 1 + (unsigned int) (max * (rand() / (1.0 + RAND_MAX)));
}

void cl_settempdir(const char *dir, short leavetemps)
{
	char *var;

    if(dir) {
	var = (char *) cli_malloc(8 + strlen(dir));
	sprintf(var, "TMPDIR=%s", dir);
	if(!putenv(var))
	    cli_dbgmsg("Setting %s as global temporary directory\n", dir);
	else
	    cli_warnmsg("Can't set TMPDIR variable - insufficient space in the environment.\n");

	/* WARNING: var must not be released - see putenv(3) */
    }

    cli_leavetemps_flag = leavetemps;
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
	return CL_EIO;
    }

    return CL_SUCCESS;
}
#endif

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

/* Function: readn
        Try hard to read the requested number of bytes
*/
int cli_readn(int fd, void *buff, unsigned int count)
{
        int retval;
        unsigned int todo;
        unsigned char *current;


        todo = count;
        current = (unsigned char *) buff;

        do {
                retval = read(fd, current, todo);
                if (retval == 0) {
                        return (count - todo);
                }
                if (retval < 0) {
			if (errno == EINTR) {
				continue;
			}
			cli_errmsg("cli_readn: read error: %s\n", strerror(errno));
                        return -1;
                }
                todo -= retval;
                current += retval;
        } while (todo > 0);


        return count;
}

/* Function: writen
        Try hard to write the specified number of bytes
*/
int cli_writen(int fd, const void *buff, unsigned int count)
{
        int retval;
        unsigned int todo;
        const unsigned char *current;


        todo = count;
        current = (const unsigned char *) buff;

        do {
                retval = write(fd, current, todo);
                if (retval < 0) {
			if (errno == EINTR) {
				continue;
			}
			cli_errmsg("cli_writen: write error: %s\n", strerror(errno));
                        return -1;
                }
                todo -= retval;
                current += retval;
        } while (todo > 0);


        return count;
}

int cli_filecopy(const char *src, const char *dest)
{
	char *buffer;
	int s, d, bytes;


    if((s = open(src, O_RDONLY|O_BINARY)) == -1)
	return -1;

    if((d = open(dest, O_CREAT|O_WRONLY|O_TRUNC|O_BINARY, S_IRWXU)) == -1) {
	close(s);
	return -1;
    }

    if(!(buffer = cli_malloc(FILEBUFF))) {
	close(s);
	close(d);
	return -1;
    }

    while((bytes = cli_readn(s, buffer, FILEBUFF)) > 0)
	cli_writen(d, buffer, bytes);

    free(buffer);
    close(s);

    return close(d);
}


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

/* returns converted timestamp, in case of error the returned string contains at least one character */
const char* cli_ctime(const time_t *timep, char *buf, const size_t bufsize)
{
	const char *ret;
	if(bufsize < 26) {
		/* standard says we must have at least 26 bytes buffer */
		cli_warnmsg("buffer too small for ctime\n");
		return " ";
	}
	if((uint32_t)(*timep) > 0x7fffffff) {
		/* some systems can consider these timestamps invalid */
		strncpy(buf, "invalid timestamp", bufsize-1);
		buf[bufsize-1] = '\0';
		return buf;
	}

#ifdef HAVE_CTIME_R	
# ifdef HAVE_CTIME_R_2
	ret = ctime_r(timep, buf);
# else
	ret = ctime_r(timep, buf, bufsize);
# endif
#else /* no ctime_r */

# ifdef CL_THREAD_SAFE
	pthread_mutex_lock(&cli_ctime_mutex);
# endif
	ret = ctime(timep);
	if(ret) {
		strncpy(buf, ret, bufsize-1);
		buf[bufsize-1] = '\0';
		ret = buf;
	}
# ifdef CL_THREAD_SAFE
	pthread_mutex_unlock(&cli_ctime_mutex);
# endif
#endif
	/* common */
	if(!ret) {
		buf[0] = ' ';
		buf[1] = '\0';
		return buf;
	}
	return ret;
}

#ifndef CLI_MEMFUNSONLY
int cli_matchregex(const char *str, const char *regex)
{
	regex_t reg;
	int match;

    if(cli_regcomp(&reg, regex, REG_EXTENDED | REG_NOSUB) == 0) {
	match = (cli_regexec(&reg, str, 0, NULL, 0) == REG_NOMATCH) ? 0 : 1;
	cli_regfree(&reg);
	return match;
    }

    return 0;
}
#endif
