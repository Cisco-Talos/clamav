/*
 *  Copyright (C) 1999-2002 Tomasz Kojm <zolw@konarski.edu.pl>
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

#include "clamav.h"
#include "others.h"
#include "md5.h"

#ifdef CL_THREAD_SAFE
# include <pthread.h>
pthread_mutex_t cli_rand_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

int cli_debug_flag = 0;

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

char *cl_strerror(int clerror)
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
	case CL_ECVDEXTR:
	     return "CVD extraction failure.";
	case CL_ENULLARG:
	    return "Null argument passed while initialized is required.";
	default:
	    return "Unknown error code.";
    }
}

char *cl_perror(int clerror)
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

char *cl_md5buff(const char *buffer, unsigned int len)
{
	unsigned char md5buf[16];
	char *md5str;
	struct md5_ctx ctx;
	int i, cnt=0;


    md5_init_ctx(&ctx);
    md5_process_bytes(buffer, len, &ctx);
    md5_finish_ctx(&ctx, &md5buf);

    md5str = (char*) cli_calloc(32 + 1, sizeof(char));

    for(i=0; i<16; i++)
	cnt += sprintf(md5str + cnt, "%02x", md5buf[i]);

    return(md5str);
}

void *cli_malloc(size_t size)
{
	void *alloc;

    alloc = malloc(size);

    if(!alloc) {
	cli_errmsg("cli_malloc(): Can't allocate memory (%d bytes).\n", size);
	perror("malloc_problem");
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

#ifndef C_URANDOM
/* it's very weak */
#include <sys/time.h>

unsigned int cl_rndnum(unsigned int max)
{
    struct timeval tv;

  gettimeofday(&tv, (struct timezone *) 0);
  srand(tv.tv_usec+clock());

  return rand() % max;
}

#else

unsigned int cl_rndnum(unsigned int max)
{
	static FILE *fd = NULL;
	unsigned int generated;
	char *byte;
	int size;

#ifdef CL_THREAD_SAFE
    pthread_mutex_lock(&cli_rand_mutex);
#endif

    if(fd == NULL) {
	if((fd = fopen("/dev/urandom", "rb")) == NULL) {
	    cli_errmsg("!Can't open /dev/urandom.\n");
#ifdef CL_THREAD_SAFE
	    pthread_mutex_unlock(&cli_rand_mutex);
#endif
	    return -1;
	}
    }

    byte = (char *) &generated;
    size = sizeof(generated);
    do {
	int bread;
	bread = fread(byte, 1, size, fd);
	size -= bread;
	byte += bread;
    } while(size > 0);

#ifdef CL_THREAD_SAFE
    pthread_mutex_unlock(&cli_rand_mutex);
#endif
    return generated % max;
}
#endif

/* it uses MD5 to avoid potential races in tmp */
char *cl_gentemp(const char *dir)
{
	char *name, *mdir, *tmp;
	unsigned char salt[32];
	int cnt=0, i;
	struct stat foo;

    if(!dir)
	mdir = "/tmp";
    else
	mdir = (char *) dir;

    name = (char*) cli_calloc(strlen(mdir) + 1 + 16 + 1, sizeof(char));
    cnt += sprintf(name, "%s/", mdir);

    do {
	for(i = 0; i < 32; i++)
	    salt[i] = cl_rndnum(255);

	tmp = cl_md5buff(salt, 32);
	strncat(name, tmp, 16);
	free(tmp);
    } while(stat(name, &foo) != -1);

    return(name);
}

int cli_rmdirs(const char *dirname)
{
	DIR *dd;
	struct dirent *dent;
	struct stat maind, statbuf;
	char *fname;

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


