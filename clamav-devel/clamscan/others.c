/*
 *  Copyright (C) 1999 - 2004 Tomasz Kojm <tkojm@clamav.net>
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
 *  Sat May 18 15:20:26 CEST 2002: included detectCpu() from Magnus Ekdahl
 *  Sat Jun 29 12:19:26 CEST 2002: fixed non386 detectCpu (Magnus Ekdahl)
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
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <time.h>
#include <fcntl.h>
#include <signal.h>
#include <pwd.h>
#include <errno.h>
#include <target.h>
#include <clamav.h>

#include "shared.h"
#include "others.h"
#include "defaults.h"
#include "treewalk.h"


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

int logg(const char *str, ...)
{
	va_list args;
	static FILE *fd = NULL;
	mode_t old_umask;


    if(logfile) {

	if (str == NULL && fd != NULL) {
	    /* re-open logfile */
	    fclose(fd);
	    fd = NULL;
	}
	if(!fd) {
            old_umask = umask(0037);
	    if((fd = fopen(logfile, "a")) == NULL) {
                umask(old_umask);
		mprintf("!LOGGER: Can't open %s for writing: %s.\n", logfile, strerror(errno));
		return 1;
	    }
	    umask(old_umask);
	}
	if (str == NULL) {
	    return 0;
	}

	va_start(args, str);

	if(*str == '!') {
	    fprintf(fd, "ERROR: ");
	    vfprintf(fd, ++str, args);
	} else if(*str == '^') {
	    fprintf(fd, "WARNING: ");
	    vfprintf(fd, ++str, args);
	} else if(*str == '*') {
	    vfprintf(fd, ++str, args);
	} else vfprintf(fd, str, args);

	va_end(args);

	fflush(fd);
    }

    return 0;
}

void *mmalloc(size_t size)
{
	void *alloc;

    alloc = malloc(size);

    if(!alloc) {
	printf("CRITICAL: Can't allocate memory (%ld bytes).\n", (long int) size);
	exit(71);
	return NULL;
    } else return alloc;
}

void *mcalloc(size_t nmemb, size_t size)
{
	void *alloc;

    alloc = calloc(nmemb, size);

    if(!alloc) {
	printf("CRITICAL: Can't allocate memory (%ld bytes).\n", (long int) nmemb * size);
	exit(70);
	return NULL;
    } else return alloc;
}

int isnumb(const char *str)
{
	int i;

    for(i = 0; i < strlen(str); i++)
	if(!isdigit(str[i]))
	    return 0;

    return 1;
}

void chomp(char *string)
{
	char *pt;

    if((pt = strchr(string, 13)))
	*pt = 0;

    if((pt = strchr(string, 10)))
	*pt = 0;
}

int fileinfo(const char *filename, short i)
{
	struct stat infostruct;

    if(stat(filename, &infostruct) == -1)
	return(-1);

    switch(i) {

	case 1: /* size */
	    return infostruct.st_size;
	case 2: /* permissions */
	    return (mode_t)infostruct.st_mode;
	case 3: /* modification time */
	    return infostruct.st_mtime;
	case 4: /* UID */
	    return infostruct.st_uid;
	case 5: /* GID */
	    return infostruct.st_gid;
	default:
	    mprintf("!fileinfo(): Unknown option.\n");
	    exit(1);
    }
}

/* these functions return pseudo random number from [0, max) */

/*
#ifdef C_LINUX
int detectcpu(void)
{
  unsigned int i=0,nrThreads=1;
  int retScan;
  char line[1000];
  char* ret;
  FILE* fs;

  if(strcmp(TARGET_OS_TYPE,"linux-gnu") != 0)
    return 1;
  if((fs = fopen("/proc/cpuinfo","r")) == NULL)
    return 1;
  do
    {
      ret = fgets(line,1000,fs);
      if(strcmp(TARGET_ARCH_TYPE,"i386") == 0 || 
	 strcmp(TARGET_ARCH_TYPE,"parisc") == 0)
	{
	  retScan = sscanf(line,"processor\t: %d",&i);
	  if(retScan != EOF && retScan != 0 && i>=nrThreads )
	    nrThreads=i+1;
	}
      else if (strcmp(TARGET_ARCH_TYPE,"ppc") == 0 || 
	       strcmp(TARGET_ARCH_TYPE,"ppc64") == 0)
	{
	  retScan = sscanf(line,"processor\t: %d",&i);
	  if(retScan != EOF && retScan != 0 && i>=nrThreads )
	    nrThreads=i+1;	  
	}
      else if (strcmp(TARGET_ARCH_TYPE,"ia64") == 0)
	{
	  retScan = sscanf(line,"processor  : %d",&i);
	  if(retScan != EOF && retScan != 0 && i>=nrThreads )
	    nrThreads=i+1;	  
	}
      else if (strcmp(TARGET_ARCH_TYPE,"alpha") == 0)
	{
	  retScan = sscanf(line,"cpus detected\t: %d",&i);
	  if (retScan != 0 && retScan != EOF)
	    return i;
	}
      else if (strcmp(TARGET_ARCH_TYPE,"s390") == 0)
	{
	  retScan = sscanf(line,"# processors    : %d",&i);
	  if (retScan != 0 && retScan != EOF)
	    return i;
	}
      else if (strcmp(TARGET_ARCH_TYPE,"sparc") == 0 || 
	       strcmp(TARGET_ARCH_TYPE,"sparc64") == 0)
	{
	  retScan = sscanf(line,"ncpus active\t: %d",&i);
	  if (retScan != 0 && retScan != EOF)
	    return i;
	}
      else if (strcmp(TARGET_ARCH_TYPE,"arm") == 0 || 
	       strcmp(TARGET_ARCH_TYPE,"m68k") == 0 || 
	       strcmp(TARGET_ARCH_TYPE,"mips") == 0 ||
	       strcmp(TARGET_ARCH_TYPE,"mips64") == 0 )
	{
	  return 1; 

	}
    }
  while(ret != NULL);

  fclose(fs);
  return nrThreads;

}
#else
int detectcpu(void)
{
    return 1;
}
#endif
*/

int readaccess(const char *path, const char *username)
{
	struct passwd *user;
	unsigned int su = 0, acc = 0;


    if(!getuid())
	su = 1;

    if(su) {
	if((user = getpwnam(username)) == NULL) {
	    return -1;
	}

	/* WARNING: it's not POSIX compliant */

	seteuid(user->pw_uid);
	setegid(user->pw_gid);
    }

    if(!access(path, R_OK))
	acc = 1;

    if(su) {
	seteuid(0);
	setegid(0);
    }

    return acc;
}

int writeaccess(const char *path, const char *username)
{
	struct passwd *user;
	unsigned int su = 0, acc = 0;


    if(!getuid())
	su = 1;

    if(su) {
	if((user = getpwnam(username)) == NULL) {
	    return -1;
	}

	/* WARNING: it's not POSIX compliant */

	seteuid(user->pw_uid);
	setegid(user->pw_gid);
    }

    if(!access(path, R_OK))
	acc = 1;

    if(su) {
	seteuid(0);
	setegid(0);
    }

    return acc;
}

int filecopy(const char *src, const char *dest)
{
	char buffer[FILEBUFF];
	int s, d, bytes;

    if((s = open(src, O_RDONLY)) == -1)
	return -1;

    if((d = open(dest, O_CREAT|O_WRONLY|O_TRUNC)) == -1) {
	close(s);
	return -1;
    }

    while((bytes = read(s, buffer, FILEBUFF)) > 0)
	write(d, buffer, bytes);

    close(s);

    /* njh@bandsman.co.uk: check result of close for NFS file */
    return close(d);
}

int strbcasestr(const char *haystack, const char *needle)
{
	char *pt = (char *) haystack;
	int i, j;

    i = strlen(haystack);
    j = strlen(needle);

    if(i < j)
	return 0;

    pt += i - j;

    return !strcasecmp(pt, needle);
}
