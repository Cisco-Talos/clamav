/*
 *  Copyright (C) 1999 - 2005 Tomasz Kojm <tkojm@clamav.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
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
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <dirent.h>
#include <time.h>
#include <fcntl.h>
#include <pwd.h>
#include <errno.h>
#include <target.h>
#include <sys/time.h>
#include <sys/param.h>

#ifdef CL_THREAD_SAFE
#  include <pthread.h>
pthread_mutex_t cli_gentemp_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

#if defined(HAVE_READDIR_R_3) || defined(HAVE_READDIR_R_2)
#include <limits.h>
#include <stddef.h>
#endif

#include "clamav.h"
#include "others.h"
#include "md5.h"
#include "cltypes.h"

/* Maximum filenames under various systems - njh */
#ifndef	NAME_MAX	/* e.g. Linux */
# ifdef	MAXNAMELEN	/* e.g. Solaris */
#   define	NAME_MAX	MAXNAMELEN
# else
#   ifdef	FILENAME_MAX	/* e.g. SCO */
#     define	NAME_MAX	FILENAME_MAX
#   else
#     define	NAME_MAX	256
#   endif
# endif
#endif

#ifndef	O_BINARY
#define	O_BINARY	0
#endif

#define CL_FLEVEL 8 /* don't touch it */

short cli_debug_flag = 0, cli_leavetemps_flag = 0;

static unsigned char oldmd5buff[16] = { 16, 38, 97, 12, 8, 4, 72, 196, 217, 144, 33, 124, 18, 11, 17, 253 };


void cli_warnmsg(const char *str, ...)
{
	va_list args;
	int sz = sizeof("LibClamAV Warning: ") - 1;
	char buff[256];

    strncpy(buff, "LibClamAV Warning: ", sz);
    va_start(args, str);
    vsnprintf(buff + sz, sizeof(buff) - sz, str, args);
    buff[sizeof(buff) - 1] = '\0';
    fputs(buff, stderr);
    va_end(args);
}

void cli_errmsg(const char *str, ...)
{
	va_list args;
	int sz = sizeof("LibClamAV Error: ") - 1;
	char buff[256];

    strncpy(buff, "LibClamAV Error: ", sz);
    va_start(args, str);
    vsnprintf(buff + sz, sizeof(buff) - sz, str, args);
    buff[sizeof(buff) - 1] = '\0';
    fputs(buff, stderr);
    va_end(args);
}

void cli_dbgmsg(const char *str, ...)
{

    if(cli_debug_flag) {
	    va_list args;
	    int sz = sizeof("LibClamAV debug: ") - 1;
	    char buff[256];

	memcpy(buff, "LibClamAV debug: ", sz);
	va_start(args, str);
	vsnprintf(buff + sz, sizeof(buff) - sz, str, args);
	buff[sizeof(buff) - 1] = '\0';
	fputs(buff, stderr);
	va_end(args);
    } else
	return;
}

void cl_debug(void)
{
    cli_debug_flag = 1;
}

int cl_retflevel(void)
{
    return CL_FLEVEL;
}

const char *cl_retver(void)
{
    return VERSION;
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
	case CL_EMALFZIP:
	    return "Malformed Zip detected";
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
	case CL_EFSYNC:
	    return "Unable to synchronize file <-> disk";
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
	default:
	    return "Unknown error code";
    }
}

const char *cl_perror(int clerror)
{
    return cl_strerror(clerror);
}

unsigned char *cli_md5digest(int desc)
{
	unsigned char *digest;
	char buff[FILEBUFF];
	MD5_CTX ctx;
	int bytes;


    if(!(digest = cli_malloc(16)))
	return NULL;

    MD5_Init(&ctx);

    while((bytes = cli_readn(desc, buff, FILEBUFF)))
	MD5_Update(&ctx, buff, bytes);

    MD5_Final(digest, &ctx);

    return digest;
}

char *cli_md5stream(FILE *fs, unsigned char *digcpy)
{
	unsigned char digest[16];
	char buff[FILEBUFF];
	MD5_CTX ctx;
	char *md5str, *pt;
	int i, bytes;


    MD5_Init(&ctx);

    while((bytes = fread(buff, 1, FILEBUFF, fs)))
	MD5_Update(&ctx, buff, bytes);

    MD5_Final(digest, &ctx);

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

static char *cli_md5buff(const char *buffer, unsigned int len)
{
	unsigned char digest[16];
	char *md5str, *pt;
	MD5_CTX ctx;
	int i;


    MD5_Init(&ctx);
    MD5_Update(&ctx, (unsigned char *) buffer, len);
    MD5_Final(digest, &ctx);
    memcpy(oldmd5buff, digest, 16);

    if(!(md5str = (char *) cli_calloc(32 + 1, sizeof(char))))
	return NULL;

    pt = md5str;
    for(i = 0; i < 16; i++) {
	sprintf(pt, "%02x", digest[i]);
	pt += 2;
    }

    return md5str;
}

void *cli_malloc(size_t size)
{
	void *alloc;


    if(!size || size > CLI_MAX_ALLOCATION) {
	cli_errmsg("Attempt to allocate %u bytes. Please report to bugs@clamav.net\n", size);
	return NULL;
    }

    alloc = malloc(size);

    if(!alloc) {
	cli_errmsg("cli_malloc(): Can't allocate memory (%u bytes).\n", size);
	perror("malloc_problem");
	/* _exit(1); */
	return NULL;
    } else return alloc;
}

void *cli_calloc(size_t nmemb, size_t size)
{
	void *alloc;


    if(!size || size > CLI_MAX_ALLOCATION) {
	cli_errmsg("Attempt to allocate %u bytes. Please report to bugs@clamav.net\n", size);
	return NULL;
    }

    alloc = calloc(nmemb, size);

    if(!alloc) {
	cli_errmsg("cli_calloc(): Can't allocate memory (%u bytes).\n", nmemb * size);
	perror("calloc_problem");
	/* _exit(1); */
	return NULL;
    } else return alloc;
}

void *cli_realloc(void *ptr, size_t size)
{
	void *alloc;


    if(!size || size > CLI_MAX_ALLOCATION) {
	cli_errmsg("Attempt to allocate %u bytes. Please report to bugs@clamav.net\n", size);
	return NULL;
    }

    alloc = realloc(ptr, size);

    if(!alloc) {
	cli_errmsg("cli_realloc(): Can't re-allocate memory to %u byte.\n", size);
	perror("realloc_problem");
	return NULL;
    } else return alloc;
}

unsigned int cli_rndnum(unsigned int max)
{
    struct timeval tv;

  gettimeofday(&tv, (struct timezone *) 0);
  srand(tv.tv_usec+clock());

  return rand() % max;
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
	struct stat foo;


    if(!dir) {
	if((mdir = getenv("TMPDIR")) == NULL)
#ifdef P_tmpdir
	    mdir = P_tmpdir;
#else
	    mdir = "/tmp";
#endif
    } else
	mdir = dir;

    name = (char*) cli_calloc(strlen(mdir) + 1 + 16 + 1 + 7, sizeof(char));
    if(name == NULL) {
	cli_dbgmsg("cli_gentemp('%s'): out of memory\n", dir);
	return NULL;
    }

#ifdef CL_THREAD_SAFE
    pthread_mutex_lock(&cli_gentemp_mutex);
#endif

    memcpy(salt, oldmd5buff, 16);

    do {
	for(i = 16; i < 48; i++)
	    salt[i] = cli_rndnum(255);

	tmp = cli_md5buff(( char* ) salt, 48);
	sprintf(name, "%s/clamav-", mdir);
	strncat(name, tmp, 16);
	free(tmp);
    } while(stat(name, &foo) != -1);

#ifdef CL_THREAD_SAFE
    pthread_mutex_unlock(&cli_gentemp_mutex);
#endif

    return(name);
}

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
	char *fname;


    chmod(dirname, 0700);
    if((dd = opendir(dirname)) != NULL) {
	while(stat(dirname, &maind) != -1) {
	    if(!rmdir(dirname)) break;
	    if(errno != ENOTEMPTY && errno != EEXIST && errno != EBADF) {
		cli_errmsg("Can't remove temporary directory %s: %s\n", dirname, strerror(errno));
		closedir(dd);
		return 0;
	    }

#ifdef HAVE_READDIR_R_3
	    while(!readdir_r(dd, &result.d, &dent) && dent) {
#elif defined(HAVE_READDIR_R_2)
	    while((dent = (struct dirent *) readdir_r(dd, &result.d))) {
#else
	    while((dent = readdir(dd))) {
#endif
#ifndef C_INTERIX
		if(dent->d_ino)
#endif
		{
		    if(strcmp(dent->d_name, ".") && strcmp(dent->d_name, "..")) {
			fname = cli_calloc(strlen(dirname) + strlen(dent->d_name) + 2, sizeof(char));
			sprintf(fname, "%s/%s", dirname, dent->d_name);

			/* stat the file */
			if(lstat(fname, &statbuf) != -1) {
			    if(S_ISDIR(statbuf.st_mode) && !S_ISLNK(statbuf.st_mode)) {
				if(rmdir(fname) == -1) { /* can't be deleted */
				    if(errno == EACCES) {
					cli_errmsg("Can't remove some temporary directories due to access problem.\n");
					closedir(dd);
					free(fname);
					return 0;
				    }
				    cli_rmdirs(fname);
				}
			    } else
				unlink(fname);
			}

			free(fname);
		    }
		}
	    }

	    rewinddir(dd);

	}

    } else { 
	return 53;
    }

    closedir(dd);
    return 0;
}

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
int cli_writen(int fd, void *buff, unsigned int count)
{
        int retval;
        unsigned int todo;
        unsigned char *current;


        todo = count;
        current = (unsigned char *) buff;

        do {
                retval = write(fd, current, todo);
                if (retval < 0) {
			if (errno == EINTR) {
				continue;
			}
                        return -1;
                }
                todo -= retval;
                current += retval;
        } while (todo > 0);


        return count;
}

int32_t cli_readint32(const char *buff)
{
	int32_t ret;

#if WORDS_BIGENDIAN == 0
    ret = *(int32_t *) buff;
#else
    ret = buff[0] & 0xff;
    ret |= (buff[1] & 0xff) << 8;
    ret |= (buff[2] & 0xff) << 16;
    ret |= (buff[3] & 0xff) << 24;
#endif

    return ret;
}

void cli_writeint32(char *offset, uint32_t value)
{
    offset[0] = value & 0xff;
    offset[1] = (value & 0xff00) >> 8;
    offset[2] = (value & 0xff0000) >> 16;
    offset[3] = (value & 0xff000000) >> 24;
}

int cli_filecopy(const char *src, const char *dest)
{
	char *buffer;
	int s, d, bytes;


    if((s = open(src, O_RDONLY)) == -1)
	return -1;

    if((d = open(dest, O_CREAT|O_WRONLY|O_TRUNC|O_BINARY)) == -1) {
	close(s);
	return -1;
    }

    if(!(buffer = cli_malloc(FILEBUFF)))
	return -1;

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

bitset_t *cli_bitset_init()
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
	
	new_length = nearest_power(min_size);
	bs->bitset = (unsigned char *) cli_realloc(bs->bitset, new_length);
	if (!bs->bitset) {
		return NULL;
	}
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
