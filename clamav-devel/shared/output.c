/*
 *  Copyright (C) 2002 - 2004 Tomasz Kojm <tkojm@clamav.net>
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
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/stat.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/socket.h>
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#if defined(USE_SYSLOG) && !defined(C_AIX)
#include <syslog.h>
#endif

#include "output.h"
#include "memory.h"

#ifdef CL_THREAD_SAFE
#include <pthread.h>
pthread_mutex_t logg_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

FILE *logg_fd = NULL;

short int logg_verbose = 0, logg_lock = 0, logg_time = 0;
int logg_size = 0;
const char *logg_file = NULL;
#if defined(USE_SYSLOG) && !defined(C_AIX)
short logg_syslog = 0;
#endif

short int mprintf_disabled = 0, mprintf_verbose = 0, mprintf_quiet = 0,
	  mprintf_stdout = 0;

int mdprintf(int desc, const char *str, ...)
{
	va_list args;
	char buff[512];
	int bytes;

    va_start(args, str);
    bytes = vsnprintf(buff, 512, str, args);
    va_end(args);
    write(desc, buff, bytes);
    return bytes;
}

void logg_close(void) {

#ifdef CL_THREAD_SAFE
    pthread_mutex_lock(&logg_mutex);
#endif
    if (logg_fd) {
	fclose(logg_fd);
	logg_fd = NULL;
    }
#ifdef CL_THREAD_SAFE
    pthread_mutex_unlock(&logg_mutex);
#endif

#if defined(USE_SYSLOG) && !defined(C_AIX)
    if(logg_syslog) {
    	closelog();
    }
#endif
}

int logg(const char *str, ...)
{
	va_list args;
	struct flock fl;
	char *pt, *timestr;
	time_t currtime;
	struct stat sb;
	mode_t old_umask;


    if(logg_file) {
#ifdef CL_THREAD_SAFE
	pthread_mutex_lock(&logg_mutex);
#endif
	if(!logg_fd) {
	    old_umask = umask(0037);
	    if((logg_fd = fopen(logg_file, "a")) == NULL) {
		umask(old_umask);
#ifdef CL_THREAD_SAFE
		pthread_mutex_unlock(&logg_mutex);
#endif
		printf("ERROR: Can't open %s in append mode.\n", logg_file);
		return -1;
	    } else umask(old_umask);

	    if(logg_lock) {
		memset(&fl, 0, sizeof(fl));
		fl.l_type = F_WRLCK;
		if(fcntl(fileno(logg_fd), F_SETLK, &fl) == -1) {
#ifdef CL_THREAD_SAFE
		    pthread_mutex_unlock(&logg_mutex);
#endif
		    return -1;
		}
	    }
	}

        /* Need to avoid logging time for verbose messages when logverbose
           is not set or we get a bunch of timestamps in the log without
           newlines... */
	if(logg_time && ((*str != '*') || logg_verbose)) {
	    time(&currtime);
	    pt = ctime(&currtime);
	    timestr = mcalloc(strlen(pt), sizeof(char));
	    strncpy(timestr, pt, strlen(pt) - 1);
	    fprintf(logg_fd, "%s -> ", timestr);
	    free(timestr);
	}

	if(logg_size) {
	    if(stat(logg_file, &sb) != -1) {
		if(sb.st_size > logg_size) {
		    logg_file = NULL;
		    fprintf(logg_fd, "Log size = %d, maximal = %d\n", (int) sb.st_size, logg_size);
		    fprintf(logg_fd, "LOGGING DISABLED (Maximal log file size exceeded).\n");
		    fclose(logg_fd);
		    logg_fd = NULL;
#ifdef CL_THREAD_SAFE
		    pthread_mutex_unlock(&logg_mutex);
#endif
		    return 0;
		}
	    }
	}

	va_start(args, str);

	if(*str == '!') {
	    fprintf(logg_fd, "ERROR: ");
	    vfprintf(logg_fd, str+1, args);
	} else if(*str == '^') {
	    fprintf(logg_fd, "WARNING: ");
	    vfprintf(logg_fd, str+1, args);
	} else if(*str == '*') {
	    if(logg_verbose)
		vfprintf(logg_fd, str+1, args);
	} else vfprintf(logg_fd, str, args);

	va_end(args);

	fflush(logg_fd);

#ifdef CL_THREAD_SAFE
	pthread_mutex_unlock(&logg_mutex);
#endif
    }

#if defined(USE_SYSLOG) && !defined(C_AIX)
    if(logg_syslog) {

      /* SYSLOG logging - no need for locking, mutexes, times & stuff ... :-) */

#ifndef vsyslog
#define vsyslog(a,b,c)	{ \
	char my_tmp[4096]; \
	vsnprintf(my_tmp,4095,b,c); \
	my_tmp[4095]=0; \
	syslog(a,my_tmp); }
#endif

	va_start(args, str);

	if(*str == '!') {
	    vsyslog(LOG_ERR, str+1, args);
	} else if(*str == '^') {
	    vsyslog(LOG_WARNING, str+1, args);
	} else if(*str == '*') {
	    if(logg_verbose) {
		vsyslog(LOG_DEBUG, str+1, args);
	    }
	} else vsyslog(LOG_INFO, str, args);

	va_end(args);
    }
#endif

    return 0;
}

void mprintf(const char *str, ...)
{
	va_list args;
	FILE *fd;
	char logbuf[512];


    if(mprintf_disabled) {
	if(*str == '@') {
	    va_start(args, str);
#ifdef NO_SNPRINTF
	    vsprintf(logbuf, ++str, args);
#else
	    vsnprintf(logbuf, sizeof(logbuf), ++str, args);
#endif
	    va_end(args);
	    logg("ERROR: %s", logbuf);
	}
	return;
    }

    if(mprintf_stdout)
	fd = stdout;
    else
	fd = stderr;

/* legend:
 * ! - error
 * @ - error with logging
 * ...
 */

/*
 *             ERROR    WARNING    STANDARD
 * normal       yes       yes        yes
 * 
 * verbose      yes       yes        yes
 * 
 * quiet        yes       no         no
 */


    va_start(args, str);

    if(*str == '!') {
	fprintf(fd, "ERROR: ");
	vfprintf(fd, ++str, args);
    } else if(*str == '@') {
	fprintf(fd, "ERROR: ");
	vfprintf(fd, ++str, args);
#ifdef NO_SNPRINTF
	vsprintf(logbuf, str, args);
#else
	vsnprintf(logbuf, sizeof(logbuf), str, args);
#endif
	logg("ERROR: %s", logbuf);
    } else if(!mprintf_quiet) {
	if(*str == '^') {
	    fprintf(fd, "WARNING: ");
	    vfprintf(fd, ++str, args);
	} else if(*str == '*') {
	    if(mprintf_verbose)
		vfprintf(fd, ++str, args);
	} else vfprintf(fd, str, args);
    }

    va_end(args);

    if(fd == stdout)
	fflush(stdout);

}
