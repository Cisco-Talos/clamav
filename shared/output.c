/*
 *  Copyright (C) 2002 - 2005 Tomasz Kojm <tkojm@clamav.net>
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
 */
#ifdef _MSC_VER
#include <windows.h>
#include <winsock.h>
#endif


#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <fcntl.h>
#include <time.h>
#include <sys/stat.h>
#include <errno.h>
#ifndef C_WINDOWS
#include <sys/time.h>
#include <sys/socket.h>
#endif
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#if defined(USE_SYSLOG) && !defined(C_AIX)
#include <syslog.h>
#endif

#include "output.h"

#ifdef CL_NOTHREADS
#undef CL_THREAD_SAFE
#endif

#ifdef CL_THREAD_SAFE
#include <pthread.h>
pthread_mutex_t logg_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

#ifdef  C_LINUX
#include <libintl.h>
#include <locale.h>

#define gettext_noop(s) s
#define _(s)    gettext(s)
#define N_(s)   gettext_noop(s)

#else

#define _(s)    s
#define N_(s)   s

#endif

FILE *logg_fd = NULL;

short int logg_verbose = 0, logg_lock = 1, logg_time = 0, logg_foreground = 1;
unsigned int logg_size = 0;
const char *logg_file = NULL;
#if defined(USE_SYSLOG) && !defined(C_AIX)
short logg_syslog;
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

    if(bytes >= (int) sizeof(buff))
	bytes = sizeof(buff) - 1;

    return send(desc, buff, bytes, 0);
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
	va_list args, argscpy, argsout;
#ifdef F_WRLCK
	struct flock fl;
#endif
	char *pt, *timestr, vbuff[1025];
	time_t currtime;
	struct stat sb;
	mode_t old_umask;


    va_start(args, str);
    /* va_copy is less portable so we just use va_start once more */
    va_start(argscpy, str);
    va_start(argsout, str);

#ifdef CL_THREAD_SAFE
    pthread_mutex_lock(&logg_mutex);
#endif
    if(logg_file) {
	if(!logg_fd) {
	    old_umask = umask(0037);
	    if((logg_fd = fopen(logg_file, "at")) == NULL) {
		umask(old_umask);
#ifdef CL_THREAD_SAFE
		pthread_mutex_unlock(&logg_mutex);
#endif
		printf("ERROR: Can't open %s in append mode (check permissions!).\n", logg_file);
		return -1;
	    } else umask(old_umask);

#ifdef F_WRLCK
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
#endif
	}

	if(logg_size) {
	    if(stat(logg_file, &sb) != -1) {
		if((unsigned int) sb.st_size > logg_size) {
		    logg_file = NULL;
		    fprintf(logg_fd, "Log size = %u, max = %u\n", (unsigned int) sb.st_size, logg_size);
		    fprintf(logg_fd, "LOGGING DISABLED (Maximal log file size exceeded).\n");
		    fclose(logg_fd);
		    logg_fd = NULL;
		}
	    }
	}

	if(logg_fd) {
            /* Need to avoid logging time for verbose messages when logverbose
               is not set or we get a bunch of timestamps in the log without
               newlines... */
	    if(logg_time && ((*str != '*') || logg_verbose)) {
		time(&currtime);
		pt = ctime(&currtime);
		timestr = calloc(strlen(pt), 1);
		strncpy(timestr, pt, strlen(pt) - 1);
		fprintf(logg_fd, "%s -> ", timestr);
		free(timestr);
	    }

	    _(str);
	    if(*str == '!') {
		fprintf(logg_fd, "ERROR: ");
		vfprintf(logg_fd, str + 1, args);
	    } else if(*str == '^') {
		fprintf(logg_fd, "WARNING: ");
		vfprintf(logg_fd, str + 1, args);
	    } else if(*str == '*') {
		if(logg_verbose)
		    vfprintf(logg_fd, str + 1, args);
	    } else if(*str == '#') {
		vfprintf(logg_fd, str + 1, args);
	    } else vfprintf(logg_fd, str, args);


	    fflush(logg_fd);
	}
    }

#if defined(USE_SYSLOG) && !defined(C_AIX)
    if(logg_syslog) {
        _(str);
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
	} else if(vbuff[0] == '#') {
	    syslog(LOG_INFO, "%s", vbuff + 1);
	} else syslog(LOG_INFO, "%s", vbuff);

    }
#endif

    if(logg_foreground) {
	_(str);
        vsnprintf(vbuff, 1024, str, argsout);
	vbuff[1024] = 0;
	if(vbuff[0] != '#')
	    mprintf("%s", vbuff);
    }

#ifdef CL_THREAD_SAFE
    pthread_mutex_unlock(&logg_mutex);
#endif

    va_end(args);
    va_end(argscpy);
    va_end(argsout);
    return 0;
}

void mprintf(const char *str, ...)
{
	va_list args;
	FILE *fd;
	char buff[512];


    if(mprintf_disabled) 
	return;

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
    vsnprintf(buff, sizeof(buff), str, args);
    va_end(args);

    if(buff[0] == '!') {
       if(!mprintf_stdout)
           fd = stderr;
	fprintf(fd, "ERROR: %s", &buff[1]);
    } else if(buff[0] == '@') {
       if(!mprintf_stdout)
           fd = stderr;
	fprintf(fd, "ERROR: %s", &buff[1]);
    } else if(!mprintf_quiet) {
	if(buff[0] == '^') {
           if(!mprintf_stdout)
               fd = stderr;
	    fprintf(fd, "WARNING: %s", &buff[1]);
	} else if(buff[0] == '*') {
	    if(mprintf_verbose)
		fprintf(fd, "%s", &buff[1]);
	} else fprintf(fd, "%s", buff);
    }

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
