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
pthread_mutex_t cl_gentemp_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

#include "clamav.h"
#include "others.h"
#include "md5.h"

#define CL_FLEVEL 2 /* don't touch it */


int cli_debug_flag = 0;

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

const char *cl_strerror(int clerror)
{
    switch(clerror) {
	case CL_CLEAN:
	    return "Virus NOT found.";
	case CL_VIRUS:
	    return "Virus(es) detected.";
	case CL_EMAXREC:
	    return "Recursion limit exceeded.";
	case CL_EMAXSIZE:
	    return "File size limit exceeded.";
	case CL_EMAXFILES:
	    return "Files number limit exceeded.";
	case CL_ERAR:
	    return "RAR module failure.";
	case CL_EZIP:
	    return "Zip module failure.";
	case CL_EMALFZIP:
	    return "Malformed Zip detected.";
	case CL_EGZIP:
	    return "GZip module failure.";
	case CL_EOLE2:
	    return "OLE2 module failure.";
	case CL_ETMPFILE:
	    return "Unable to create temporary file.";
	case CL_ETMPDIR:
	    return "Unable to create temporary directory.";
	case CL_EFSYNC:
	    return "Unable to synchronize file <-> disk.";
	case CL_EMEM:
	    return "Unable to allocate memory.";
	case CL_EOPEN:
	    return "Unable to open file or directory.";
	case CL_EMALFDB:
	    return "Malformed database.";
	case CL_EPATSHORT:
	    return "Too short pattern detected.";
	case CL_ECVD:
	    return "Broken or not a CVD file.";
	case CL_ECVDEXTR:
	    return "CVD extraction failure.";
	case CL_EMD5:
	    return "MD5 verification error.";
	case CL_EDSIG:
	    return "Digital signature verification error.";
	case CL_ENULLARG:
	    return "Null argument passed while initialized is required.";
	default:
	    return "Unknown error code.";
    }
}

const char *cl_perror(int clerror)
{
    return cl_strerror(clerror);
}

char *cl_md5file(const char *filename)
{
	FILE *fd;
	unsigned char buffer[16];
	char *md5str;
	int i, cnt=0;

    if((fd = fopen(filename, "rb")) == NULL) {
	cli_errmsg("md5_file(): Can't read file %s\n", filename);
	return NULL;
    }

    md5_stream(fd, &buffer);
    fclose(fd);

    md5str = (char*) calloc(32 + 1, sizeof(char));

    for(i=0; i<16; i++)
	cnt += sprintf(md5str + cnt, "%02x", buffer[i]);

    return(md5str);
}

char *cli_md5stream(FILE *fd)
{
	unsigned char buffer[16];
	char *md5str;
	int i, cnt=0;

    md5_stream(fd, &buffer);

    md5str = (char*) calloc(32 + 1, sizeof(char));

    for(i=0; i<16; i++)
	cnt += sprintf(md5str + cnt, "%02x", buffer[i]);

    return(md5str);
}

char *cl_md5buff(const char *buffer, unsigned int len)
{
	unsigned char md5buff[16];
	char *md5str;
	struct md5_ctx ctx;
	int i, cnt=0;


    md5_init_ctx(&ctx);
    md5_process_bytes(buffer, len, &ctx);
    md5_finish_ctx(&ctx, &md5buff);
    memcpy(oldmd5buff, md5buff, 16);

    md5str = (char*) cli_calloc(32 + 1, sizeof(char));

    for(i=0; i<16; i++)
	cnt += sprintf(md5str + cnt, "%02x", md5buff[i]);

    return(md5str);
}

void *cli_malloc(size_t size)
{
	void *alloc;

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

unsigned int cl_rndnum(unsigned int max)
{
    struct timeval tv;

  gettimeofday(&tv, (struct timezone *) 0);
  srand(tv.tv_usec+clock());

  return rand() % max;
}

char *cl_gentemp(const char *dir)
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
	cli_dbgmsg("cl_gentemp('%s'): out of memory\n", dir);
	return NULL;
    }

#ifdef CL_THREAD_SAFE
    pthread_mutex_lock(&cl_gentemp_mutex);
#endif

    memcpy(salt, oldmd5buff, 16);

    do {
	for(i = 16; i < 48; i++)
	    salt[i] = cl_rndnum(255);

	tmp = cl_md5buff(( char* ) salt, 48);
	sprintf(name, "%s/clamav-", mdir);
	strncat(name, tmp, 16);
	free(tmp);
    } while(stat(name, &foo) != -1);

#ifdef CL_THREAD_SAFE
    pthread_mutex_unlock(&cl_gentemp_mutex);
#endif

    return(name);
}

int cli_rmdirs(const char *dirname)
{
	DIR *dd;
	struct dirent *dent;
	struct stat maind, statbuf;
	char *fname;


    if(cli_debug_flag)
	return 0;

    chmod(dirname, 0700);
    if((dd = opendir(dirname)) != NULL) {
	while(stat(dirname, &maind) != -1) {
	    if(!rmdir(dirname)) break;

	    while((dent = readdir(dd))) {
		if(dent->d_ino) {
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

