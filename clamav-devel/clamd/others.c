/*
 *  Copyright (C) 2002, 2003 Tomasz Kojm <zolw@konarski.edu.pl>
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

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <time.h>
#include <sys/stat.h>

#if defined(CLAMD_USE_SYSLOG) && !defined(C_AIX)
#include <syslog.h>
#endif

#include "others.h"

pthread_mutex_t logg_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t rand_mutex = PTHREAD_MUTEX_INITIALIZER;

FILE *log_fd = NULL;

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
    pthread_mutex_lock(&logg_mutex);
    if (log_fd) {
	fclose(log_fd);
    }
    pthread_mutex_unlock(&logg_mutex);
#if defined(CLAMD_USE_SYSLOG) && !defined(C_AIX)
    if(use_syslog) {
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


    if(logfile) {

	pthread_mutex_lock(&logg_mutex);

	if(!log_fd) {
	    old_umask = umask(0036);
	    if((log_fd = fopen(logfile, "a")) == NULL) {
		umask(old_umask);
		pthread_mutex_unlock(&logg_mutex);
		return -1;
	    } else umask(old_umask);

	    if(loglock) {
		memset(&fl, 0, sizeof(fl));
		fl.l_type = F_WRLCK;
		if(fcntl(fileno(log_fd), F_SETLK, &fl) == -1) {
		    pthread_mutex_unlock(&logg_mutex);
		    return -1;
		}
	    }
	}

        /* Need to avoid logging time for verbose messages when logverbose
           is not set or we get a bunch of timestamps in the log without
           newlines... */
	if(logtime && ((*str != '*') || logverbose)) {
	    time(&currtime);
	    pt = ctime(&currtime);
	    timestr = mcalloc(strlen(pt), sizeof(char));
	    strncpy(timestr, pt, strlen(pt) - 1);
	    fprintf(log_fd, "%s -> ", timestr);
	    free(timestr);
	}


	if(logsize) {
	    if(stat(logfile, &sb) != -1) {
		if(sb.st_size > logsize) {
		    logfile = NULL;
		    fprintf(log_fd, "Log size = %d, maximal = %d\n", (int) sb.st_size, logsize);
		    fprintf(log_fd, "LOGGING DISABLED (Maximal log file size exceeded).\n");
		    fclose(log_fd);
		    pthread_mutex_unlock(&logg_mutex);
		    return 0;
		}
	    }
	}

	va_start(args, str);

	if(*str == '!') {
	    fprintf(log_fd, "ERROR: ");
	    vfprintf(log_fd, ++str, args);
	} else if(*str == '^') {
	    fprintf(log_fd, "WARNING: ");
	    vfprintf(log_fd, ++str, args);
	} else if(*str == '*') {
	    if(logverbose)
		vfprintf(log_fd, ++str, args);
	} else vfprintf(log_fd, str, args);

	va_end(args);

	fflush(log_fd);
	pthread_mutex_unlock(&logg_mutex);
    }

#if defined(CLAMD_USE_SYSLOG) && !defined(C_AIX)
    if(use_syslog) {

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
	    vsyslog(LOG_ERR,++str, args);
	} else if(*str == '^') {
	    vsyslog(LOG_WARNING,++str, args);
	} else if(*str == '*') {
	    if(logverbose)
		vsyslog(LOG_DEBUG, ++str, args);
	} else vsyslog(LOG_INFO, str, args);

	va_end(args);
    }
#endif

    return 0;
}

int isnumb(const char *str)
{
	int i;

    for(i = 0; i < strlen(str); i++)
	if(!isdigit(str[i]))
	    return 0;

    return 1;
}

void *mmalloc(size_t size)
{
	void *alloc;

    alloc = malloc(size);

    if(!alloc) {
	printf("CRITICAL: Can't allocate memory (%d bytes).\n", size);
	exit(71);
	return NULL;
    } else return alloc;
}

void *mcalloc(size_t nmemb, size_t size)
{
	void *alloc;

    alloc = calloc(nmemb, size);

    if(!alloc) {
	printf("CRITICAL: Can't allocate memory (%d bytes).\n", nmemb * size);
	exit(70);
	return NULL;
    } else return alloc;
}

void chomp(char *string)
{
	char *pt;

    if((pt = strchr(string, 13)))
	*pt = 0;

    if((pt = strchr(string, 10)))
	*pt = 0;
}

void virusaction(const char *filename, const char *virname, const struct cfgstruct *copt)
{
	char *buffer, *pt, *cmd;
	struct cfgstruct *cpt;


    if(!(cpt = cfgopt(copt, "VirusEvent")))
	return;

    cmd = strdup(cpt->strarg);

    buffer = (char *) mcalloc(strlen(cmd) + strlen(filename) + strlen(virname) + 10, sizeof(char));

    if((pt = strstr(cmd, "%f"))) {
	*pt = 0; pt += 2;
	strcpy(buffer, cmd);
	strcat(buffer, filename);
	strcat(buffer, pt);
	free(cmd);
	cmd = strdup(buffer);
    }

    if((pt = strstr(cmd, "%v"))) {
	*pt = 0; pt += 2;
	strcpy(buffer, cmd);
	strcat(buffer, virname);
	strcat(buffer, pt);
	free(cmd);
	cmd = strdup(buffer);
    }

    free(buffer);

    /* WARNING: this is uninterruptable ! */
    system(cmd);

    free(cmd);
}
