/*
 *  Copyright (C) 1999 - 2004 Tomasz Kojm <tk@clamav.net>
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

#ifdef CL_THREAD_SAFE
#  include <pthread.h>
pthread_mutex_t cli_gentemp_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

#include "clamav.h"
#include "others.h"
#include "md5.h"
#include "cltypes.h"

#define CL_FLEVEL 3 /* don't touch it */

#define MAX_ALLOCATION 134217728

short cli_debug_flag = 0, cli_leavetemps_flag = 0;

static unsigned char oldmd5buff[16] = { 16, 38, 97, 12, 8, 4, 72, 196, 217, 144, 33, 124, 18, 11, 17, 253 };

void cli_warnmsg(const char *str, ...)
{
	va_list args;

    va_start(args, str);
    fprintf(stderr, "LibClamAV Warning: ");
    vfprintf(stderr, str, args);
    va_end(args);
}

void cli_errmsg(const char *str, ...)
{
	va_list args;

    va_start(args, str);
    fprintf(stderr, "LibClamAV Error: ");
    vfprintf(stderr, str, args);
    va_end(args);
}

void cli_dbgmsg(const char *str, ...)
{
	va_list args;

    if(cli_debug_flag) {
	va_start(args, str);
	fprintf(stderr, "LibClamAV debug: ");
	vfprintf(stderr, str, args);
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

char *cli_md5stream(FILE *fs, unsigned char *digcpy)
{
	unsigned char digest[16];
	char buff[FILEBUFF];
	struct MD5Context ctx;
	char *md5str, *pt;
	int i, bytes;


    MD5Init(&ctx);

    while((bytes = fread(buff, 1, FILEBUFF, fs)))
	MD5Update(&ctx, buff, bytes);

    MD5Final(digest, &ctx);

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
	struct MD5Context ctx;
	int i;


    MD5Init(&ctx);
    MD5Update(&ctx, buffer, len);
    MD5Final(digest, &ctx);
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


    if(size > MAX_ALLOCATION || size < 0) {
	cli_errmsg("Attempt to allocate %d bytes. Please report to bugs@clamav.net\n", size);
	return NULL;
    }

    alloc = malloc(size);

    if(!alloc) {
	cli_errmsg("cli_malloc(): Can't allocate memory (%d bytes).\n", size);
	perror("malloc_problem");
	/* _exit(1); */
	return NULL;
    } else return alloc;
}

void *cli_calloc(size_t nmemb, size_t size)
{
	void *alloc;


    if(size > MAX_ALLOCATION || size < 0) {
	cli_errmsg("Attempt to allocate %d bytes. Please report to bugs@clamav.net\n", size);
	return NULL;
    }

    alloc = calloc(nmemb, size);

    if(!alloc) {
	cli_errmsg("cli_calloc(): Can't allocate memory (%d bytes).\n", nmemb * size);
	perror("calloc_problem");
	/* _exit(1); */
	return NULL;
    } else return alloc;
}

void *cli_realloc(void *ptr, size_t size)
{
	void *alloc;


    alloc = realloc(ptr, size);

    if(!alloc) {
	cli_errmsg("cli_realloc(): Can't re-allocate memory to %d byte.\n", size);
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


    if(!dir)
	mdir = "/tmp";
    else
	mdir = (char *) dir;

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
	struct dirent result;
#endif
	struct stat maind, statbuf;
	char *fname;


    chmod(dirname, 0700);
    if((dd = opendir(dirname)) != NULL) {
	while(stat(dirname, &maind) != -1) {
	    if(!rmdir(dirname)) break;

#ifdef HAVE_READDIR_R_3
	    while(!readdir_r(dd, &result, &dent) && dent) {
#elif defined(HAVE_READDIR_R_2)
	    while((dent = (struct dirent *) readdir_r(dd, &result))) {
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
	int32_t shift, i = 0;

    ret = 0;
    for(shift = 0; shift < 32; shift += 8) {
      ret |= (buff[i] & 0xff ) << shift;
      i++;
    }
#endif

    return ret;
}

int cli_memstr(const char *haystack, int hs, const char *needle, int ns)
{
	const char *pt, *hay;
	int n;


    if(hs < ns)
	return 0;

    if(haystack == needle)
	return 1;

    if(!memcmp(haystack, needle, ns))
	return 1;

    pt = hay = haystack;
    n = hs;

    while((pt = memchr(hay, needle[0], n)) != NULL) {
	n -= (int) pt - (int) hay;
	if(n < ns)
	    break;

	if(!memcmp(pt, needle, ns))
	    return 1;

	if(hay == pt) {
	    n--;
	    hay++;
	} else {
	    hay = pt;
	}
    }

    return 0;
}
