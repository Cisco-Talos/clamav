/*
 *  Copyright (C) 2002 - 2005 Tomasz Kojm <tkojm@clamav.net>
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

#ifdef CL_NOTHREADS
#undef CL_THREAD_SAFE
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

FILE *logg_fs = NULL;

short int logg_verbose = 0, logg_lock = 1, logg_time = 0;
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
    bytes = vsnprintf(buff, sizeof(buff), str, args);
    va_end(args);

    if(bytes == -1)
	return bytes;

    if(bytes >= sizeof(buff))
	bytes = sizeof(buff) - 1;

    return send(desc, buff, bytes, 0);
}

void logg_close(void) {

#ifdef CL_THREAD_SAFE
    pthread_mutex_lock(&logg_mutex);
#endif
    if (logg_fs) {
	fclose(logg_fs);
	logg_fs = NULL;
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
	va_list args, argscpy;
	struct flock fl;
	char *pt, *timestr, vbuff[1025];
	time_t currtime;
	struct stat sb;
	mode_t old_umask;


    va_start(args, str);
    /* va_copy is less portable so we just use va_start once more */
    va_start(argscpy, str);

    if(logg_file) {
#ifdef CL_THREAD_SAFE
	pthread_mutex_lock(&logg_mutex);
#endif
	if(!logg_fs) {
	    old_umask = umask(0037);
	    if((logg_fs = fopen(logg_file, "a")) == NULL) {
		umask(old_umask);
#ifdef CL_THREAD_SAFE
		pthread_mutex_unlock(&logg_mutex);
#endif
		printf("ERROR: Can't open %s in append mode (check permissions!).\n", logg_file);
		return -1;
	    } else umask(old_umask);

	    if(logg_lock) {
		memset(&fl, 0, sizeof(fl));
		fl.l_type = F_WRLCK;
		if(fcntl(fileno(logg_fs), F_SETLK, &fl) == -1) {
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
	    fprintf(logg_fs, "%s -> ", timestr);
	    free(timestr);
	}

	if(logg_size) {
	    if(stat(logg_file, &sb) != -1) {
		if(sb.st_size > logg_size) {
		    logg_file = NULL;
		    fprintf(logg_fs, "Log size = %d, maximal = %d\n", (int) sb.st_size, logg_size);
		    fprintf(logg_fs, "LOGGING DISABLED (Maximal log file size exceeded).\n");
		    fclose(logg_fs);
		    logg_fs = NULL;
#ifdef CL_THREAD_SAFE
		    pthread_mutex_unlock(&logg_mutex);
#endif
		    return 0;
		}
	    }
	}


	if(*str == '!') {
	    fprintf(logg_fs, "ERROR: ");
	    vfprintf(logg_fs, str + 1, args);
	} else if(*str == '^') {
	    fprintf(logg_fs, "WARNING: ");
	    vfprintf(logg_fs, str + 1, args);
	} else if(*str == '*') {
	    if(logg_verbose)
		vfprintf(logg_fs, str + 1, args);
	} else vfprintf(logg_fs, str, args);


	fflush(logg_fs);

#ifdef CL_THREAD_SAFE
	pthread_mutex_unlock(&logg_mutex);
#endif
    }

#if defined(USE_SYSLOG) && !defined(C_AIX)
    if(logg_syslog) {
	vsnprintf(vbuff, 1024, str, argscpy);
	vbuff[1024] = 0;

	if(vbuff[0] == '!') {
	    syslog(LOG_ERR, "%s", vbuff + 1);
	} else if(vbuff[0] == '^') {
	    syslog(LOG_WARNING, "%s", vbuff + 1);
	} else if(vbuff[0] == '*') {
	    if(logg_verbose) {
		syslog(LOG_DEBUG, "%s", vbuff + 1);
	    }
	} else syslog(LOG_INFO, "%s", vbuff);

    }
#endif

    va_end(args);
    va_end(argscpy);
    return 0;
}

void mprintf(const char *str, ...)
{
	va_list args, argscpy;
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

    fd = stdout;

/* legend:
 * ! - error
 * @ - error with logging
 * ...
 */

/*
 *             ERROR    WARNING    STANDARD
 * normal      stderr   stderr     stdout
 * 
 * verbose     stderr   stderr     stdout
 * 
 * quiet       stderr     no         no
 */


    va_start(args, str);
    /* va_copy is less portable so we just use va_start once more */
    va_start(argscpy, str);

    if(*str == '!') {
       if(!mprintf_stdout)
           fd = stderr;
	fprintf(fd, "ERROR: ");
	vfprintf(fd, ++str, args);
    } else if(*str == '@') {
       if(!mprintf_stdout)
           fd = stderr;
	fprintf(fd, "ERROR: ");
	vfprintf(fd, ++str, args);
#ifdef NO_SNPRINTF
	vsprintf(logbuf, str, argscpy);
#else
	vsnprintf(logbuf, sizeof(logbuf), str, argscpy);
#endif
	logg("ERROR: %s", logbuf);
    } else if(!mprintf_quiet) {
	if(*str == '^') {
           if(!mprintf_stdout)
               fd = stderr;
	    fprintf(fd, "WARNING: ");
	    vfprintf(fd, ++str, args);
	} else if(*str == '*') {
	    if(mprintf_verbose)
		vfprintf(fd, ++str, args);
	} else vfprintf(fd, str, args);
    }

    va_end(args);
    va_end(argscpy);

    if(fd == stdout)
	fflush(stdout);

}

struct facstruct {
    const char *name;
    int code;
};

#if defined(USE_SYSLOG) && !defined(C_AIX)
static const struct facstruct facilitymap[] = {
#ifdef LOG_AUTH
    { "LOG_AUTH",	LOG_AUTH },
#endif
#ifdef LOG_AUTHPRIV
    { "LOG_AUTHPRIV",	LOG_AUTHPRIV },
#endif
#ifdef LOG_CRON
    { "LOG_CRON",	LOG_CRON },
#endif
#ifdef LOG_DAEMON
    { "LOG_DAEMON",	LOG_DAEMON },
#endif
#ifdef LOG_FTP
    { "LOG_FTP",	LOG_FTP },
#endif
#ifdef LOG_KERN
    { "LOG_KERN",	LOG_KERN },
#endif
#ifdef LOG_LPR
    { "LOG_LPR",	LOG_LPR },
#endif
#ifdef LOG_MAIL
    { "LOG_MAIL",	LOG_MAIL },
#endif
#ifdef LOG_NEWS
    { "LOG_NEWS",	LOG_NEWS },
#endif
#ifdef LOG_AUTH
    { "LOG_AUTH",	LOG_AUTH },
#endif
#ifdef LOG_SYSLOG
    { "LOG_SYSLOG",	LOG_SYSLOG },
#endif
#ifdef LOG_USER
    { "LOG_USER",	LOG_USER },
#endif
#ifdef LOG_UUCP
    { "LOG_UUCP",	LOG_UUCP },
#endif
#ifdef LOG_LOCAL0
    { "LOG_LOCAL0",	LOG_LOCAL0 },
#endif
#ifdef LOG_LOCAL1
    { "LOG_LOCAL1",	LOG_LOCAL1 },
#endif
#ifdef LOG_LOCAL2
    { "LOG_LOCAL2",	LOG_LOCAL2 },
#endif
#ifdef LOG_LOCAL3
    { "LOG_LOCAL3",	LOG_LOCAL3 },
#endif
#ifdef LOG_LOCAL4
    { "LOG_LOCAL4",	LOG_LOCAL4 },
#endif
#ifdef LOG_LOCAL5
    { "LOG_LOCAL5",	LOG_LOCAL5 },
#endif
#ifdef LOG_LOCAL6
    { "LOG_LOCAL6",	LOG_LOCAL6 },
#endif
#ifdef LOG_LOCAL7
    { "LOG_LOCAL7",	LOG_LOCAL7 },
#endif
    { NULL,		-1 }
};

int logg_facility(const char *name)
{
	int i;

    for(i = 0; facilitymap[i].name; i++)
	if(!strcmp(facilitymap[i].name, name))
	    return facilitymap[i].code;

    return -1;
}
#endif
